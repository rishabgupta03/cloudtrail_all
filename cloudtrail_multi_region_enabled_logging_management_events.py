#!/usr/bin/env python3
"""
Control: CloudTrail logs management events for read and write operations.

get_event_selectors returns either the classic EventSelectors format or the
newer AdvancedEventSelectors format (a trail uses one or the other). Both
are checked for full read+write coverage of Management events:
  - Classic: a selector with IncludeManagementEvents=True and
    ReadWriteType=All (or separate ReadOnly + WriteOnly selectors together).
  - Advanced: a selector targeting eventCategory=Management with no readOnly
    restriction (covers both), or both readOnly=true and readOnly=false
    present across selectors.
Multi-region trails are only evaluated once, in their HomeRegion, to avoid
double-counting.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail Logs Management Events For Read And Write Operations"

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


def evaluate_advanced_selectors(advanced_selectors):
    mgmt_selectors = [
        s for s in advanced_selectors
        if any(
            fs.get("Field") == "eventCategory" and "Management" in fs.get("Equals", [])
            for fs in s.get("FieldSelectors", [])
        )
    ]
    if not mgmt_selectors:
        return "NON_COMPLIANT", "No advanced event selector targets the Management event category"

    covers_read = False
    covers_write = False
    for s in mgmt_selectors:
        readonly_fs = next((fs for fs in s.get("FieldSelectors", []) if fs.get("Field") == "readOnly"), None)
        if readonly_fs is None:
            covers_read = covers_write = True
        else:
            vals = readonly_fs.get("Equals", [])
            if "true" in vals:
                covers_read = True
            if "false" in vals:
                covers_write = True

    if covers_read and covers_write:
        return "COMPLIANT", "Advanced event selector(s) log Management events for both read and write operations"

    missing = [name for name, ok in (("read", covers_read), ("write", covers_write)) if not ok]
    return "NON_COMPLIANT", f"Advanced event selector(s) do not cover {' and '.join(missing)} management operations"


def evaluate_basic_selectors(basic_selectors):
    mgmt_selectors = [s for s in basic_selectors if s.get("IncludeManagementEvents")]
    if not mgmt_selectors:
        return "NON_COMPLIANT", "No event selector has IncludeManagementEvents enabled"

    rw_types = {s.get("ReadWriteType", "All") for s in mgmt_selectors}
    if "All" in rw_types:
        return "COMPLIANT", "Event selector logs management events with ReadWriteType=All (covers read and write)"
    if {"ReadOnly", "WriteOnly"}.issubset(rw_types):
        return "COMPLIANT", "Separate event selectors cover ReadOnly and WriteOnly management events (both covered)"

    return "NON_COMPLIANT", f"Management event selector(s) only cover: {', '.join(rw_types)} - both read and write required"


def evaluate_trail_event_selectors(client, trail_arn):
    """Return (status, evidence) for one trail's management event coverage."""
    resp = client.get_event_selectors(TrailName=trail_arn)
    advanced_selectors = resp.get("AdvancedEventSelectors", [])
    basic_selectors = resp.get("EventSelectors", [])

    if advanced_selectors:
        return evaluate_advanced_selectors(advanced_selectors)
    if basic_selectors:
        return evaluate_basic_selectors(basic_selectors)
    return "NON_COMPLIANT", "No event selectors configured - management events are not being logged"


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

            try:
                status, evidence = evaluate_trail_event_selectors(client, trail_arn)
                if status == "COMPLIANT":
                    compliant += 1
                elif status == "NON_COMPLIANT":
                    non_compliant += 1
                else:
                    skipped += 1
            except ClientError as e:
                _, reason = classify_error(e)
                status = "SKIPPED"
                evidence = f"Could not fetch event selectors: {reason}"
                skipped += 1
            except Exception as e:
                status = "SKIPPED"
                evidence = f"Could not evaluate trail: {e}"
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
    filename = f"cloudtrail_management_events_rw_{account_id}_{timestamp}.csv"
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