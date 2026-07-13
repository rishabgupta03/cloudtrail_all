#!/usr/bin/env python3
"""
Control: CloudTrail logs show no potential enumeration activity.

IMPORTANT - read before relying on this script:
This is a heuristic behavioral check, not a configuration compliance check
like the other scripts in this set. AWS's purpose-built tool for detecting
real reconnaissance/enumeration is GuardDuty (finding types such as
"Discovery:S3/BucketEnumeration.Unusual" and "Recon:IAMUser/*"), which uses
ML models over CloudTrail data. Since this control specifically asks about
CloudTrail logs, this script analyzes raw lookup_events output directly,
but that means it WILL produce false positives (legitimate bulk automation
looks identical to recon) and false negatives (slow, spread-out enumeration
will not trip a burst threshold). Treat NON_COMPLIANT findings here as a
lead to investigate, not a confirmed incident - and treat any GuardDuty
Discovery/Recon findings as the higher-confidence source if available.

Heuristic: for each region, pull read-only List*/Describe*/Get* events over
a lookback window, group by identity (Username), and sliding-window over
each identity's timeline to look for either (a) a burst of calls or (b) a
burst of distinct AWS services touched, within a short time window.
Exceeding either tunable threshold flags that identity, marking the region
NON_COMPLIANT. Evaluated per-region, since this is about activity across
the account rather than a specific resource's configuration.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "CloudTrail Logs Show No Potential Enumeration Activity"
ENUMERATION_PREFIXES = ("List", "Describe", "Get")
MAX_EVENTS_PER_REGION = 10000  # safety cap so a very active account doesn't run unbounded
TOP_FLAGGED_IN_EVIDENCE = 5

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
        "InvalidTimeRangeException": "Invalid lookback time range requested",
    }
    return code, reasons.get(code, f"AWS error ({code})")


def fetch_enumeration_events(client, start_time, end_time):
    """Fetch read-only events from lookup_events, filtered client-side to
    List*/Describe*/Get* names, capped at MAX_EVENTS_PER_REGION. Returns
    (events, truncated: bool)."""
    events = []
    truncated = False
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "true"}],
    ):
        for event in page.get("Events", []):
            name = event.get("EventName", "")
            if name.startswith(ENUMERATION_PREFIXES):
                events.append({
                    "time": event.get("EventTime"),
                    "name": name,
                    "source": event.get("EventSource", "unknown"),
                    "identity": event.get("Username") or f"accesskey:{event.get('AccessKeyId', 'unknown')}",
                })
                if len(events) >= MAX_EVENTS_PER_REGION:
                    truncated = True
                    return events, truncated
    return events, truncated


def sliding_window_stats(events_for_identity, window):
    """Given one identity's (time, source) events sorted by time, return
    (max_call_count, max_distinct_services) seen in any window-sized slice."""
    left = 0
    service_counts = Counter()
    max_count = 0
    max_distinct = 0
    for right in range(len(events_for_identity)):
        service_counts[events_for_identity[right][1]] += 1
        while events_for_identity[right][0] - events_for_identity[left][0] > window:
            src = events_for_identity[left][1]
            service_counts[src] -= 1
            if service_counts[src] == 0:
                del service_counts[src]
            left += 1
        count = right - left + 1
        distinct = len(service_counts)
        max_count = max(max_count, count)
        max_distinct = max(max_distinct, distinct)
    return max_count, max_distinct


def evaluate_region_activity(events, window, call_threshold, service_threshold):
    """Return (status, evidence) for one region's enumeration heuristic."""
    if not events:
        return "COMPLIANT", "No read-only List/Describe/Get events found in the lookback window to analyze"

    by_identity = defaultdict(list)
    for e in events:
        by_identity[e["identity"]].append((e["time"], e["source"]))

    flagged = []
    for identity, ev_list in by_identity.items():
        ev_list.sort(key=lambda x: x[0])
        max_count, max_distinct = sliding_window_stats(ev_list, window)
        if max_count >= call_threshold or max_distinct >= service_threshold:
            flagged.append((identity, max_count, max_distinct))

    if not flagged:
        return "COMPLIANT", (
            f"No burst pattern exceeded thresholds across {len(by_identity)} identity(ies) "
            f"and {len(events)} enumeration-style event(s) analyzed"
        )

    flagged.sort(key=lambda x: (x[1], x[2]), reverse=True)
    shown = flagged[:TOP_FLAGGED_IN_EVIDENCE]
    detail = "; ".join(f"{ident} (peak {cnt} calls / {dist} services in window)" for ident, cnt, dist in shown)
    more = f" (+{len(flagged) - TOP_FLAGGED_IN_EVIDENCE} more)" if len(flagged) > TOP_FLAGGED_IN_EVIDENCE else ""
    return "NON_COMPLIANT", (
        f"Potential enumeration burst pattern detected for {len(flagged)} identity(ies): {detail}{more}. "
        f"Heuristic only - investigate before treating as confirmed; cross-check GuardDuty Discovery/Recon findings."
    )


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, account_id, regions, lookback_hours, window_minutes, call_threshold, service_threshold):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)
    window = timedelta(minutes=window_minutes)

    print(f"\nRegions to Scan: {len(regions)}")
    print(f"Lookback: {lookback_hours}h | Window: {window_minutes}m | Call threshold: {call_threshold} | Service threshold: {service_threshold}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            client = session.client("cloudtrail", region_name=region)
            events, truncated = fetch_enumeration_events(client, start_time, end_time)
        except (ClientError, EndpointConnectionError) as e:
            reason = classify_error(e)[1] if isinstance(e, ClientError) else "CloudTrail endpoint not available in this region"
            skipped += 1
            results.append({"Region": region, "Status": "SKIPPED", "Evidence": reason})
            continue
        except NoCredentialsError:
            skipped += 1
            results.append({"Region": region, "Status": "SKIPPED", "Evidence": "No valid credentials available"})
            continue

        try:
            status, evidence = evaluate_region_activity(events, window, call_threshold, service_threshold)
            if truncated:
                evidence += f" (NOTE: event fetch capped at {MAX_EVENTS_PER_REGION} - analysis based on partial data)"
        except Exception as e:
            status = "SKIPPED"
            evidence = f"Could not evaluate region activity: {e}"

        total_checked += 1
        if status == "COMPLIANT":
            compliant += 1
        elif status == "NON_COMPLIANT":
            non_compliant += 1
        else:
            skipped += 1

        results.append({"Region": region, "Status": status, "Evidence": evidence})

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloudtrail_enumeration_activity_{account_id}_{timestamp}.csv"
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
    parser.add_argument("--lookback-hours", type=int, default=24, help="Hours of CloudTrail history to analyze (max ~2160 / 90 days)")
    parser.add_argument("--window-minutes", type=int, default=10, help="Sliding time window size in minutes for burst detection")
    parser.add_argument("--call-threshold", type=int, default=50, help="Flag an identity if it makes >= this many enumeration-style calls within the window")
    parser.add_argument("--distinct-service-threshold", type=int, default=8, help="Flag an identity if it touches >= this many distinct AWS services within the window")
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
        session, account_id, regions,
        args.lookback_hours, args.window_minutes, args.call_threshold, args.distinct_service_threshold,
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
    print("\nReminder: this is a heuristic check over raw CloudTrail events, not a")
    print("definitive detection. Cross-check any NON_COMPLIANT region against")
    print("GuardDuty Discovery:*/Recon:* findings before treating as an incident.")


if __name__ == "__main__":
    main()