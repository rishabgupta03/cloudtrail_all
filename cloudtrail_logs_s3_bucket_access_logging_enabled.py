#!/usr/bin/env python3
"""
Control: CloudTrail destination S3 bucket has access logging enabled.
For each trail, resolves S3BucketName and checks get_bucket_logging on
that bucket. Since multiple trails can share a destination bucket, results
are cached per bucket name for the run. Multi-region trails are only
evaluated once, in their HomeRegion, to avoid double-counting.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail Destination S3 Bucket Has Access Logging Enabled"

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


def check_bucket_logging(session, bucket_name, cache):
    """Return (status, evidence) for one S3 bucket's access logging config,
    cached per bucket name since multiple trails can share a destination bucket."""
    if bucket_name in cache:
        return cache[bucket_name]

    try:
        region = resolve_bucket_region(session, bucket_name)
        s3 = session.client("s3", region_name=region)
        logging_resp = s3.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" in logging_resp:
            target = logging_resp["LoggingEnabled"].get("TargetBucket", "N/A")
            result = ("COMPLIANT", f"S3 access logging enabled on '{bucket_name}' (target bucket: {target})")
        else:
            result = ("NON_COMPLIANT", f"S3 access logging is not enabled on destination bucket '{bucket_name}'")
    except ClientError as e:
        _, reason = classify_error(e)
        result = ("SKIPPED", f"Could not check logging on bucket '{bucket_name}': {reason}")

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
                    status, evidence = check_bucket_logging(session, bucket_name, bucket_cache)
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
    filename = f"cloudtrail_s3_destination_logging_{account_id}_{timestamp}.csv"
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