#!/usr/bin/env python3
"""
Control     : CloudTrail has insights enabled
Description : For every enabled region, lists all home-region CloudTrail
              trails and checks whether CloudTrail Insights is configured
              on each one via get_insight_selectors.

              A trail is compliant if its InsightSelectors list is
              non-empty - meaning at least one of the two available
              insight types is enabled:
              - ApiCallRateInsight  : detects unusual API call volumes
              - ApiErrorRateInsight : detects unusual API error rates

              InsightNotEnabledException from get_insight_selectors is
              treated as NON_COMPLIANT (not SKIPPED) - it is the expected
              AWS response when Insights has never been configured, not a
              permissions or availability issue.

              Region handling: describe_trails(includeShadowTrails=False)
              returns only home-region trails per region scan, avoiding
              double-counting of multi-region trail shadow copies.
"""

import argparse
import csv

import boto3
from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail Has Insights Enabled"


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


def evaluate_insights(ct_client, trail_arn: str, trail_name: str):
    """
    Returns (status: str, evidence: str).

    Calls get_insight_selectors and evaluates the result:
    - Non-empty InsightSelectors           -> COMPLIANT
    - Empty InsightSelectors               -> NON_COMPLIANT
    - InsightNotEnabledException           -> NON_COMPLIANT (expected when
                                              Insights has never been set)
    - Any other ClientError / BotoCoreError -> SKIPPED
    """
    try:
        response = ct_client.get_insight_selectors(TrailName=trail_arn)
        selectors = response.get("InsightSelectors", [])
        insight_types = [s.get("InsightType", "unknown") for s in selectors]

        if insight_types:
            return (
                "COMPLIANT",
                f"CloudTrail Insights enabled - type(s): {', '.join(insight_types)}",
            )
        return (
            "NON_COMPLIANT",
            "Insights selector list is empty - no insight types are configured",
        )

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "InsightNotEnabledException":
            return (
                "NON_COMPLIANT",
                "CloudTrail Insights is not enabled on this trail "
                "(InsightNotEnabledException)",
            )
        # All other client errors - cannot determine status
        return "SKIPPED", explain_error(e, "cloudtrail:GetInsightSelectors")

    except BotoCoreError as e:
        return "SKIPPED", explain_error(e, "cloudtrail:GetInsightSelectors")


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

    for region in tqdm(regions, desc="Scanning regions"):
        try:
            ct = session.client("cloudtrail", region_name=region)
        except (ClientError, BotoCoreError) as e:
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": explain_error(e, "boto3 client creation"),
            })
            continue

        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        except (ClientError, BotoCoreError) as e:
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": explain_error(e, "cloudtrail:DescribeTrails"),
            })
            continue

        for trail in trails:
            trail_name = trail.get("Name", "N/A")
            trail_arn = trail.get("TrailARN", (
                f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"
            ))

            status, evidence = evaluate_insights(ct, trail_arn, trail_name)
            total_checked += 1

            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
                skipped += 1
                total_checked -= 1

            results.append({
                "Region": region, "ResourceId": trail_name,
                "ResourceArn": trail_arn, "Status": status, "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"cloudtrail_insights_enabled_{account_id}.csv"
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
        overall = "NO CLOUDTRAIL TRAILS FOUND"
    elif non_compliant > 0:
        overall = "NON_COMPLIANT"
    else:
        overall = "COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("=" * 60)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()