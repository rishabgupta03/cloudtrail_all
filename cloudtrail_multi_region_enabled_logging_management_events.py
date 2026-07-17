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

Multi-region trails apply their logging configuration to every region in
the account, so - to match how they're reported by GRC/compliance tooling -
a multi-region trail is evaluated ONCE (in its HomeRegion, where
get_event_selectors is called), and that same result is then recorded for
every region it is visible in. This produces one result row per region per
trail, matching resource-per-region reporting conventions, while only
making the AWS API call once per trail.
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
    """Map a ClientError to a short, human-readable reason, with the raw
    AWS error code/message appended so root cause is visible in the CSV."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    raw_message = e.response.get("Error", {}).get("Message", str(e))
    reasons = {
        "AccessDeniedException": "Access denied - insufficient IAM permissions",
        "AccessDenied": "Access denied - insufficient IAM permissions",
        "ThrottlingException": "Throttled by AWS API - request rate exceeded",
        "InvalidClientTokenId": "Invalid/expired credentials for this region",
        "TrailNotFoundException": "Trail not found (may have been deleted)",
    }
    friendly = reasons.get(code, f"AWS error ({code})")
    return code, f"{friendly} | raw: {code}: {raw_message}"


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

    # Cache of trail_arn -> (status, evidence, is_multi_region, home_region)
    # so a multi-region trail's event selectors are only fetched from AWS
    # once, even though its result gets recorded once per region below.
    trail_eval_cache = {}
    # Track (region, trail_arn) pairs we've already appended to results,
    # in case list_trails ever returns duplicates within the same region.
    seen_region_trail = set()

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
            if (region, trail_arn) in seen_region_trail:
                continue
            seen_region_trail.add((region, trail_arn))

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

            trail_name = trail_info.get("Name", "N/A")
            home_region = trail_info.get("HomeRegion")
            is_multi_region = bool(trail_info.get("IsMultiRegionTrail"))

            # Evaluate the trail's event selectors once (cached per trail_arn).
            # For a multi-region trail this call is made against its
            # HomeRegion client the first time it's encountered; the cached
            # result is then reused for every other region it appears in.
            if trail_arn not in trail_eval_cache:
                try:
                    status, evidence = evaluate_trail_event_selectors(client, trail_arn)
                except ClientError as e:
                    _, reason = classify_error(e)
                    status, evidence = "SKIPPED", f"Could not fetch event selectors: {reason}"
                except Exception as e:
                    status, evidence = "SKIPPED", f"Could not evaluate trail: {e}"
                trail_eval_cache[trail_arn] = (status, evidence)
            else:
                status, evidence = trail_eval_cache[trail_arn]

            # Annotate evidence with multi-region / home-region context so
            # rows for the same trail read consistently across every region,
            # matching how multi-region trails are reported in region-scoped
            # compliance inventories.
            if is_multi_region and home_region:
                evidence = f"Trail '{trail_name}' from home region {home_region} is multi-region. {evidence}"

            total_checked += 1
            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
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
    parser.add_argument(
        "--region",
        help="Only scan this region (e.g. ap-south-1) instead of all enabled regions. "
             "Multi-region trails still show up here if AWS's list_trails "
             "surfaces them in this region.",
        default=None,
    )
    args = parser.parse_args()

    try:
        session = get_session(args.role_arn)
        account_id = get_account_id(session)
        regions = [args.region] if args.region else get_regions(session)
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

    skipped_rows = [r for r in results if r["Status"] == "SKIPPED"]
    if skipped_rows:
        print("\nSKIPPED DETAILS:")
        print("-" * 60)
        for r in skipped_rows:
            print(f"[{r['Region']}] {r['TrailName']}: {r['Evidence']}")
        print("-" * 60)


if __name__ == "__main__":
    main()
