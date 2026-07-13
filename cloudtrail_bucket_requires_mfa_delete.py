#!/usr/bin/env python3
"""
Control     : CloudTrail S3 bucket has MFA delete enabled
Description : Scans all regions for CloudTrail trails, collects the unique
              set of S3 buckets referenced by those trails, then checks
              each bucket's versioning configuration for MFA delete status.

              Deduplication: the same S3 bucket can serve multiple trails.
              Each unique bucket is evaluated exactly once - the evidence
              names all trails that reference it so the finding is fully
              traceable.

              MFA delete requires bucket versioning to be enabled first.
              A bucket with versioning suspended or disabled cannot have
              MFA delete enabled - this is surfaced as a distinct
              NON_COMPLIANT message rather than a generic one.

              Cross-account buckets: CloudTrail can write to a bucket in
              a different AWS account. If get_bucket_versioning returns
              access denied, the bucket is marked SKIPPED with a clear
              cross-account note - it is not a script error.

              Region handling: describe_trails(includeShadowTrails=False)
              returns only home-region trails per region scan, avoiding
              double-counting of multi-region trail shadow copies.
              S3 bucket checks use a single global S3 client since bucket
              versioning is account-level, not region-scoped.
"""

import argparse
import csv
from collections import defaultdict

import boto3
from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail S3 Bucket Has MFA Delete Enabled"


# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None) -> Session:
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


def get_account_id(session: Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session: Session) -> list:
    """All opted-in regions enabled for this account."""
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


def get_service_regions(session: Session, service_name: str) -> list:
    """Enabled regions intersected with regions boto3 knows the service has endpoints in."""
    enabled = set(get_regions(session))
    supported = set(session.get_available_regions(service_name))
    return sorted(enabled & supported)


# ==================================================
# HELPERS
# ==================================================
def explain_error(e: Exception, action: str = "") -> str:
    """
    Short, human-readable reason for a skip - names the exact API action
    that failed so a denial is debuggable straight from the CSV.
    """
    where = f" calling {action}" if action else ""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "ClientError")
        if code in ("AccessDeniedException", "UnauthorizedException", "AccessDenied"):
            return f"Access denied - missing IAM permission for {action or 'this call'}"
        return f"AWS error{where}: {code}"
    if isinstance(e, BotoCoreError):
        return f"Client/connection error{where}: {e.__class__.__name__}"
    return f"Unexpected error{where}: {e.__class__.__name__}: {e}"


def collect_trail_buckets(session: Session, regions: list) -> dict:
    """
    Scans all regions for CloudTrail trails and returns a dict mapping
    each unique S3 bucket name to the list of trail ARNs that reference it.
    Uses includeShadowTrails=False to avoid double-counting multi-region
    trail shadow copies.
    Skipped regions are silently omitted - the caller gets what's findable.
    """
    bucket_to_trails = defaultdict(list)

    for region in tqdm(regions, desc="Collecting trails"):
        try:
            ct = session.client("cloudtrail", region_name=region)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            for trail in trails:
                bucket = trail.get("S3BucketName")
                trail_arn = trail.get("TrailARN", trail.get("Name", "unknown"))
                if bucket:
                    bucket_to_trails[bucket].append(trail_arn)
        except (ClientError, BotoCoreError):
            # Region-level failure during collection - will surface as
            # missing trails in results, not a hard stop
            pass

    return dict(bucket_to_trails)


def get_bucket_region(s3_client, bucket: str) -> str:
    """Returns the AWS region the bucket is located in, or 'unknown' on failure."""
    try:
        location = s3_client.get_bucket_location(Bucket=bucket)
        return location.get("LocationConstraint") or "us-east-1"
    except (ClientError, BotoCoreError):
        return "unknown"


def mfa_delete_status(s3_client, bucket: str):
    """
    Returns (status: str, evidence: str) by checking get_bucket_versioning.

    MFA delete states:
    - versioning absent / suspended + no MFADelete field -> NON_COMPLIANT
    - versioning enabled + MFADelete == 'Enabled'        -> COMPLIANT
    - versioning enabled + MFADelete != 'Enabled'        -> NON_COMPLIANT
    - versioning not enabled at all                      -> NON_COMPLIANT
      (MFA delete cannot be enabled without versioning)
    """
    response = s3_client.get_bucket_versioning(Bucket=bucket)
    versioning_status = response.get("Status", "")
    mfa_delete = response.get("MFADelete", "")

    if mfa_delete == "Enabled":
        return (
            "COMPLIANT",
            f"MFA delete is enabled (versioning: {versioning_status or 'not configured'})",
        )

    if not versioning_status or versioning_status == "Suspended":
        return (
            "NON_COMPLIANT",
            f"MFA delete is not enabled and versioning is "
            f"'{versioning_status or 'not configured'}' - "
            f"versioning must be enabled before MFA delete can be configured",
        )

    return (
        "NON_COMPLIANT",
        f"Versioning is '{versioning_status}' but MFA delete is "
        f"'{mfa_delete or 'Disabled'}' - MFA delete must be explicitly enabled",
    )


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session: Session):
    account_id = get_account_id(session)
    regions = get_service_regions(session, "cloudtrail")

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to scan : {len(regions)}\n")

    # Phase 1 - collect all unique buckets across all regions
    bucket_to_trails = collect_trail_buckets(session, regions)

    if not bucket_to_trails:
        print("\nNo CloudTrail trails with S3 buckets found.\n")
        return results, total_checked, compliant, non_compliant, skipped

    print(f"\nUnique S3 buckets to evaluate : {len(bucket_to_trails)}\n")

    # Phase 2 - evaluate each unique bucket once
    s3 = session.client("s3", region_name="us-east-1")

    for bucket, trail_arns in tqdm(bucket_to_trails.items(), desc="Evaluating buckets"):
        bucket_region = get_bucket_region(s3, bucket)
        resource_arn = f"arn:aws:s3:::{bucket}"
        trail_summary = (
            ", ".join(trail_arns[:3]) + (f" (+{len(trail_arns) - 3} more)" if len(trail_arns) > 3 else "")
        )

        try:
            status, detail = mfa_delete_status(s3, bucket)
            total_checked += 1
            if status == "COMPLIANT":
                compliant += 1
            else:
                non_compliant += 1
            evidence = f"{detail} | Referenced by trail(s): {trail_summary}"

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            skipped += 1
            if code in ("AccessDenied", "AccessDeniedException"):
                evidence = (
                    f"Access denied reading bucket versioning - bucket may be in a "
                    f"cross-account or restricted configuration | "
                    f"Referenced by trail(s): {trail_summary}"
                )
            else:
                evidence = f"{explain_error(e, 's3:GetBucketVersioning')} | Referenced by trail(s): {trail_summary}"
            status = "SKIPPED"

        except BotoCoreError as e:
            skipped += 1
            status = "SKIPPED"
            evidence = f"{explain_error(e, 's3:GetBucketVersioning')} | Referenced by trail(s): {trail_summary}"

        results.append({
            "Region": bucket_region,
            "ResourceId": bucket,
            "ResourceArn": resource_arn,
            "Status": status,
            "Evidence": evidence,
        })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"cloudtrail_s3_bucket_mfa_delete_enabled_{account_id}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"],
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

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    print("=" * 60)
    print(f"CONTROL : {CONTROL_NAME}")
    print(f"ACCOUNT : {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = check_control(session)
    if total_checked == 0 and skipped > 0:
        overall = "INCONCLUSIVE - all resources skipped, see CSV Evidence column"
    elif total_checked == 0:
        overall = "NO CLOUDTRAIL S3 BUCKETS FOUND"
    elif non_compliant > 0:
        overall = "NON_COMPLIANT"
    else:
        overall = "COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("=" * 60)
    print(f"Total Checked   : {total_checked}  (unique S3 buckets)")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()