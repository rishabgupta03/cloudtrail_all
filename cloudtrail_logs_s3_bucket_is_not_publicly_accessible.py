#!/usr/bin/env python3
"""
Control: CloudTrail trail S3 bucket is not publicly accessible.

Evaluates effective public access rather than a simplified 2-flag check:
  1. If all 4 PublicAccessBlockConfiguration flags are True, the bucket is
     fully locked down regardless of any underlying ACL/policy -> COMPLIANT.
  2. Otherwise, checks whether the bucket ACL actually grants access to the
     AllUsers/AuthenticatedUsers groups, and whether get_bucket_policy_status
     reports the bucket policy as public.
  3. If PAB is not fully enabled but neither the ACL nor the policy actually
     grants public access, this is still COMPLIANT - but the evidence notes
     the weaker posture so it can be hardened proactively.

Results are cached per bucket name (multiple trails can share a destination
bucket) and multi-region trails are only evaluated once, in their
HomeRegion, to avoid double-counting.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail S3 Bucket Is Not Publicly Accessible"
PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
PAB_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="control-audit")
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def classify_error(e):
    """Map a ClientError to a short, human-readable reason."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    reasons = {
        "AccessDeniedException": "Access denied - insufficient IAM permissions",
        "AccessDenied": "Access denied - insufficient IAM permissions",
        "ThrottlingException": "Throttled by AWS API - request rate exceeded",
        "InvalidClientTokenId": "Invalid/expired credentials for this region",
        "TrailNotFoundException": "Trail not found (may have been deleted)",
        "NoSuchBucket": "Destination S3 bucket no longer exists",
    }
    return code, reasons.get(code, f"AWS error ({code})")


def resolve_bucket_region(session, bucket_name):
    s3_us_east_1 = session.client("s3", region_name="us-east-1")
    location = s3_us_east_1.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
    if not location:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return location


def get_public_access_block(s3_client, bucket_name):
    try:
        return s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {k: False for k in PAB_KEYS}
        raise


def bucket_acl_is_public(s3_client, bucket_name):
    resp = s3_client.get_bucket_acl(Bucket=bucket_name)
    for grant in resp.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_ACL_URIS:
            return True
    return False


def bucket_policy_is_public(s3_client, bucket_name):
    try:
        return s3_client.get_bucket_policy_status(Bucket=bucket_name)["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def check_bucket_public_access(session, bucket_name, cache):
    """Return (status, evidence) for one S3 bucket's effective public
    accessibility, cached per bucket name since multiple trails can share
    a destination bucket."""
    if bucket_name in cache:
        return cache[bucket_name]

    try:
        region = resolve_bucket_region(session, bucket_name)
        s3 = session.client("s3", region_name=region)
        pab = get_public_access_block(s3, bucket_name)
        fully_blocked = all(pab.get(k, False) for k in PAB_KEYS)

        if fully_blocked:
            result = ("COMPLIANT", f"Bucket '{bucket_name}' fully blocks public access (all 4 Block Public Access settings enabled)")
        else:
            acl_public = bucket_acl_is_public(s3, bucket_name)
            policy_public = bucket_policy_is_public(s3, bucket_name)

            if acl_public or policy_public:
                reasons = []
                if acl_public:
                    reasons.append("bucket ACL grants access to AllUsers/AuthenticatedUsers")
                if policy_public:
                    reasons.append("bucket policy grants public access")
                result = ("NON_COMPLIANT", f"Bucket '{bucket_name}' is publicly accessible - {'; '.join(reasons)}")
            else:
                result = ("COMPLIANT", (
                    f"Bucket '{bucket_name}' is not currently publicly accessible (no public ACL grants, "
                    f"no public bucket policy), but Block Public Access is not fully enabled ({pab}) - "
                    f"consider enabling all 4 settings for defense in depth"
                ))
    except ClientError as e:
        _, reason = classify_error(e)
        result = ("SKIPPED", f"Could not evaluate public access for bucket '{bucket_name}': {reason}")

    cache[bucket_name] = result
    return result


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, account_id, regions):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0
    bucket_cache = {}

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            client = session.client("cloudtrail", region_name=region)
            trail_arns = []
            for page in client.get_paginator("list_trails").paginate():
                trail_arns.extend(t["TrailARN"] for t in page.get("Trails", []))
        except (ClientError, EndpointConnectionError) as e:
            reason = classify_error(e)[1] if isinstance(e, ClientError) else "CloudTrail endpoint not available in this region"
            skipped += 1
            results.append({
                "Region": region, "TrailName": "N/A", "TrailArn": "N/A",
                "Status": "SKIPPED", "Evidence": reason,
            })
            continue
        except NoCredentialsError:
            skipped += 1
            results.append({
                "Region": region, "TrailName": "N/A", "TrailArn": "N/A",
                "Status": "SKIPPED", "Evidence": "No valid credentials available",
            })
            continue

        for trail_arn in tqdm(trail_arns, desc=f"  {region}", leave=False):
            try:
                trail_info = client.get_trail(Name=trail_arn)["Trail"]
            except ClientError as e:
                _, reason = classify_error(e)
                skipped += 1
                results.append({
                    "Region": region, "TrailName": trail_arn, "TrailArn": trail_arn,
                    "Status": "SKIPPED", "Evidence": f"Could not fetch trail details: {reason}",
                })
                continue

            home_region = trail_info.get("HomeRegion")
            if home_region and home_region != region:
                # Multi-region trail surfaced from a non-home region - evaluated
                # once already (or will be) in its home region, skip here entirely.
                continue

            total_checked += 1
            trail_name = trail_info.get("Name", "N/A")
            bucket_name = trail_info.get("S3BucketName")

            if not bucket_name:
                status, evidence = "SKIPPED", "Trail has no S3BucketName configured - cannot evaluate"
                skipped += 1
            else:
                try:
                    status, evidence = check_bucket_public_access(session, bucket_name, bucket_cache)
                    if status == "COMPLIANT":
                        compliant += 1
                    elif status == "NON_COMPLIANT":
                        non_compliant += 1
                    else:
                        skipped += 1
                except Exception as e:
                    status = "SKIPPED"
                    evidence = f"Could not evaluate destination bucket: {e}"
                    skipped += 1

            results.append({
                "Region": region, "TrailName": trail_name, "TrailArn": trail_arn,
                "Status": status, "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloudtrail_s3_bucket_public_access_{account_id}_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Account", "Region", "TrailName", "TrailArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({"Account": account_id, **row})
    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(description=CONTROL_NAME)
    parser.add_argument("-R", "--role-arn", help="IAM role ARN to assume", default=None)
    args = parser.parse_args()

    try:
        session = get_session(args.role_arn)
        account_id = get_account_id(session)
        regions = get_regions(session)
    except (ClientError, NoCredentialsError) as e:
        print(f"FATAL: Could not establish session/credentials - {e}")
        sys.exit(1)

    print("=" * 60)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = check_control(
        session, account_id, regions
    )

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Control       : {CONTROL_NAME}")
    print(f"Account       : {account_id}")
    print(f"Total Checked : {total_checked}")
    print(f"Compliant     : {compliant}")
    print(f"Non-Compliant : {non_compliant}")
    print(f"Skipped       : {skipped}")
    print(f"Overall       : {overall}")
    print(f"CSV Report    : {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()