#!/usr/bin/env python3
"""
Control: Region has at least one CloudTrail logging.

This is evaluated per-region rather than per-resource, in two phases:
  1. Discovery - scan every enabled region, collect all trails (deduped by
     ARN, since a multi-region trail surfaces in every region's list_trails),
     and record each trail's HomeRegion, IsMultiRegionTrail, and whether it
     is actively logging (get_trail_status().IsLogging).
  2. Evaluation - a region is COMPLIANT if either (a) any multi-region trail
     in the account is actively logging (covers every region), or (b) the
     region has its own region-specific trail that is actively logging.
     Otherwise NON_COMPLIANT.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "Region Has At Least One CloudTrail Logging"

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
    }
    return code, reasons.get(code, f"AWS error ({code})")


def discover_trails(session, regions):
    """Phase 1: collect every trail in the account (deduped by ARN) with its
    HomeRegion, IsMultiRegionTrail, and live logging status. Returns
    (trails: list[dict], discovery_errors: {region: reason})."""
    trails_by_arn = {}
    discovery_errors = {}

    for region in tqdm(regions, desc="Discovering Trails"):
        try:
            client = session.client("cloudtrail", region_name=region)
            trail_arns = []
            for page in client.get_paginator("list_trails").paginate():
                trail_arns.extend(t["TrailARN"] for t in page.get("Trails", []))
        except (ClientError, EndpointConnectionError) as e:
            discovery_errors[region] = classify_error(e)[1] if isinstance(e, ClientError) else "CloudTrail endpoint not available in this region"
            continue
        except NoCredentialsError:
            discovery_errors[region] = "No valid credentials available"
            continue

        for trail_arn in trail_arns:
            if trail_arn in trails_by_arn:
                continue
            try:
                trail_info = client.get_trail(Name=trail_arn)["Trail"]
                status = client.get_trail_status(Name=trail_arn)
                trails_by_arn[trail_arn] = {
                    "Name": trail_info.get("Name", "N/A"),
                    "Arn": trail_arn,
                    "HomeRegion": trail_info.get("HomeRegion"),
                    "IsMultiRegionTrail": trail_info.get("IsMultiRegionTrail", False),
                    "IsLogging": status.get("IsLogging", False),
                }
            except ClientError as e:
                _, reason = classify_error(e)
                trails_by_arn[trail_arn] = {
                    "Name": trail_arn, "Arn": trail_arn, "HomeRegion": None,
                    "IsMultiRegionTrail": False, "IsLogging": False, "Error": reason,
                }

    return list(trails_by_arn.values()), discovery_errors


def evaluate_region(region, all_trails, discovery_errors):
    """Return (status, evidence) for one region's CloudTrail coverage."""
    active_multi_region = [t for t in all_trails if t["IsMultiRegionTrail"] and t["IsLogging"]]
    if active_multi_region:
        names = ", ".join(t["Name"] for t in active_multi_region)
        return "COMPLIANT", f"Covered by actively-logging multi-region trail(s): {names}"

    if region in discovery_errors:
        return "SKIPPED", f"Could not determine coverage for this region: {discovery_errors[region]}"

    region_trails = [t for t in all_trails if t["HomeRegion"] == region and t["IsLogging"]]
    if region_trails:
        names = ", ".join(t["Name"] for t in region_trails)
        return "COMPLIANT", f"Covered by actively-logging region-specific trail(s): {names}"

    return "NON_COMPLIANT", "No actively-logging CloudTrail trail (region-specific or multi-region) covers this region"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, account_id, regions):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    all_trails, discovery_errors = discover_trails(session, regions)

    for region in tqdm(regions, desc="Evaluating Regions"):
        total_checked += 1
        try:
            status, evidence = evaluate_region(region, all_trails, discovery_errors)
            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
                skipped += 1
        except Exception as e:
            status = "SKIPPED"
            evidence = f"Could not evaluate region: {e}"
            skipped += 1

        results.append({"Region": region, "Status": status, "Evidence": evidence})

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloudtrail_region_coverage_{account_id}_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Account", "Region", "Status", "Evidence"])
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