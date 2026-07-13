#!/usr/bin/env python3
"""
Control     : CloudTrail has delivered logs to CloudWatch Logs in the last
              24 hours
Description : For every enabled region, lists all home-region CloudTrail
              trails and checks whether each one has successfully delivered
              logs to CloudWatch Logs within the last 24 hours.

              Three distinct evaluation cases:
              1. No CloudWatch Logs log group configured on the trail
                 -> NON_COMPLIANT (delivery is structurally impossible)
              2. CWL configured, LatestCloudWatchLogsDeliveryTime within
                 24 hours -> COMPLIANT
              3. CWL configured but delivery time absent or older than
                 24 hours -> NON_COMPLIANT with exact age of last delivery
                 so the auditor knows how stale it is

              If a delivery error is also present on the trail, it is
              appended to the evidence regardless of compliance status
              so it is visible in the CSV without opening the console.

              Region handling: describe_trails(includeShadowTrails=False)
              returns only home-region trails per region scan, avoiding
              double-counting of multi-region trail shadow copies.
              get_trail_status is called once per trail.
"""

import argparse
import csv
from datetime import datetime, timedelta, timezone

import boto3
from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail Has Delivered Logs To CloudWatch Logs In The Last 24 Hours"
DELIVERY_WINDOW_HOURS = 24


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


def format_age(delivery_time: datetime, now: datetime) -> str:
    """Returns a human-readable age string like '2h 15m ago' or '3d 4h ago'."""
    delta = now - delivery_time
    total_seconds = int(delta.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days > 0:
        return f"{days}d {hours}h ago"
    if hours > 0:
        return f"{hours}h {minutes}m ago"
    return f"{minutes}m ago"


def evaluate_trail(trail: dict, trail_status: dict, now: datetime):
    """
    Returns (status: str, evidence: str).

    Checks CloudWatch Logs configuration then delivery recency.
    Appends any active delivery error to evidence regardless of status.
    """
    trail_name = trail.get("Name", "unknown")
    cwl_log_group = trail.get("CloudWatchLogsLogGroupArn", "")
    delivery_error = trail_status.get("LatestCloudWatchLogsDeliveryError", "")
    delivery_time = trail_status.get("LatestCloudWatchLogsDeliveryTime")

    # Append delivery error suffix to evidence if present
    error_suffix = (
        f" | Latest delivery error: {delivery_error}" if delivery_error else ""
    )

    # Case 1 - no CWL configured
    if not cwl_log_group:
        return (
            "NON_COMPLIANT",
            f"No CloudWatch Logs log group configured on trail '{trail_name}' - "
            f"logs cannot be delivered to CloudWatch Logs{error_suffix}",
        )

    log_group_name = cwl_log_group.split(":")[-2] if ":" in cwl_log_group else cwl_log_group

    # Case 2 - never delivered
    if not delivery_time:
        return (
            "NON_COMPLIANT",
            f"CloudWatch Logs log group '{log_group_name}' is configured but "
            f"no successful delivery has ever been recorded{error_suffix}",
        )

    # Normalise to UTC-aware datetime
    if delivery_time.tzinfo is None:
        delivery_time = delivery_time.replace(tzinfo=timezone.utc)

    age = format_age(delivery_time, now)
    delivery_time_str = delivery_time.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Case 3 - delivered but too long ago
    if now - delivery_time > timedelta(hours=DELIVERY_WINDOW_HOURS):
        return (
            "NON_COMPLIANT",
            f"Last delivery to CloudWatch Logs log group '{log_group_name}' was "
            f"{age} ({delivery_time_str}) - exceeds {DELIVERY_WINDOW_HOURS}h "
            f"threshold{error_suffix}",
        )

    # Case 4 - delivered within window
    return (
        "COMPLIANT",
        f"Logs delivered to CloudWatch Logs log group '{log_group_name}' "
        f"{age} ({delivery_time_str}){error_suffix}",
    )


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session: Session):
    account_id = get_account_id(session)
    regions = get_service_regions(session, "cloudtrail")
    now = datetime.now(timezone.utc)

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
            trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}")

            try:
                trail_status = ct.get_trail_status(Name=trail_arn)
            except (ClientError, BotoCoreError) as e:
                skipped += 1
                results.append({
                    "Region": region, "ResourceId": trail_name,
                    "ResourceArn": trail_arn, "Status": "SKIPPED",
                    "Evidence": explain_error(e, "cloudtrail:GetTrailStatus"),
                })
                continue

            total_checked += 1
            status, evidence = evaluate_trail(trail, trail_status, now)

            if status == "COMPLIANT":
                compliant += 1
            else:
                non_compliant += 1

            results.append({
                "Region": region, "ResourceId": trail_name,
                "ResourceArn": trail_arn, "Status": status, "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"cloudtrail_cloudwatch_logs_delivery_24h_{account_id}.csv"
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