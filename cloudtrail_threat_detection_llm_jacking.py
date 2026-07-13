#!/usr/bin/env python3
"""
Control: No potential LLM-jacking activity detected in CloudTrail.

IMPORTANT - read before relying on this script:
"LLM-jacking" refers to stolen/compromised credentials being used to run
unauthorized inference against Amazon Bedrock, typically for resale on
underground marketplaces or to drain a victim account's budget. This is a
heuristic behavioral check over raw CloudTrail events, not a configuration
compliance check. AWS GuardDuty has dedicated Bedrock protection with
finding types built specifically for this (abnormal model invocation
patterns, foundation model abuse) using ML models with far more context
than this script has. If GuardDuty Bedrock protection is enabled, treat its
findings as the authoritative source and this script as a supplementary
raw-log view. This script WILL produce false positives (a legitimate
high-volume Bedrock application looks identical to abuse) and false
negatives (a slow, low-and-slow abuse pattern will not trip a threshold).

Heuristic: for each region, pull Bedrock-related events (event sources
bedrock.amazonaws.com and bedrock-runtime.amazonaws.com) over a lookback
window, split into invocation events (InvokeModel/Converse/etc, the
billable calls) and enumeration events (ListFoundationModels/etc, the
reconnaissance calls attackers use to find which models a stolen
credential can access). Group by identity and sliding-window over each
identity's timeline for: (a) an invocation call burst, (b) a burst of
distinct models invoked, or (c) enumeration and invocation activity both
present for the same identity - the strongest combined signal. Any of
these flags the identity and marks the region NON_COMPLIANT.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from tqdm import tqdm

CONTROL_NAME = "No Potential LLM-Jacking Activity Detected In CloudTrail"
BEDROCK_EVENT_SOURCES = ("bedrock.amazonaws.com", "bedrock-runtime.amazonaws.com")
INVOKE_EVENT_NAMES = ("InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream")
ENUMERATION_EVENT_NAMES = ("ListFoundationModels", "GetFoundationModel", "ListCustomModels", "GetFoundationModelAvailability")
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


def fetch_bedrock_events(client, start_time, end_time):
    """Fetch Bedrock-related events (both control-plane and runtime event
    sources, queried separately since LookupEvents accepts one attribute
    filter per call), capped at MAX_EVENTS_PER_REGION. Returns
    (events, truncated: bool)."""
    events = []
    truncated = False
    for source in BEDROCK_EVENT_SOURCES:
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": source}],
        ):
            for event in page.get("Events", []):
                name = event.get("EventName", "")
                if name not in INVOKE_EVENT_NAMES and name not in ENUMERATION_EVENT_NAMES:
                    continue
                resources = event.get("Resources", [])
                model_id = resources[0].get("ResourceName", "unknown-model") if resources else "unknown-model"
                events.append({
                    "time": event.get("EventTime"),
                    "name": name,
                    "model": model_id,
                    "identity": event.get("Username") or f"accesskey:{event.get('AccessKeyId', 'unknown')}",
                    "is_invoke": name in INVOKE_EVENT_NAMES,
                })
                if len(events) >= MAX_EVENTS_PER_REGION:
                    truncated = True
                    return events, truncated
    return events, truncated


def sliding_window_stats(events_for_identity, window):
    """Given one identity's (time, model, is_invoke) events sorted by time,
    return (max_invoke_count, max_distinct_models, has_enumeration) seen in
    any window-sized slice."""
    left = 0
    model_counts = Counter()
    max_invoke_count = 0
    max_distinct_models = 0
    saw_enumeration = any(not e[2] for e in events_for_identity)
    for right in range(len(events_for_identity)):
        if events_for_identity[right][2]:
            model_counts[events_for_identity[right][1]] += 1
        while events_for_identity[right][0] - events_for_identity[left][0] > window:
            if events_for_identity[left][2]:
                m = events_for_identity[left][1]
                model_counts[m] -= 1
                if model_counts[m] == 0:
                    del model_counts[m]
            left += 1
        invoke_count = sum(1 for i in range(left, right + 1) if events_for_identity[i][2])
        distinct_models = len(model_counts)
        max_invoke_count = max(max_invoke_count, invoke_count)
        max_distinct_models = max(max_distinct_models, distinct_models)
    return max_invoke_count, max_distinct_models, saw_enumeration


def evaluate_region_activity(events, window, call_threshold, model_threshold, combined_threshold):
    """Return (status, evidence) for one region's LLM-jacking heuristic."""
    if not events:
        return "COMPLIANT", "No Bedrock invocation or enumeration events found in the lookback window to analyze"

    by_identity = defaultdict(list)
    for e in events:
        by_identity[e["identity"]].append((e["time"], e["model"], e["is_invoke"]))

    flagged = []
    for identity, ev_list in by_identity.items():
        ev_list.sort(key=lambda x: x[0])
        max_invoke, max_models, has_enum = sliding_window_stats(ev_list, window)
        reasons = []
        if max_invoke >= call_threshold:
            reasons.append(f"invocation burst ({max_invoke} calls in window)")
        if max_models >= model_threshold:
            reasons.append(f"multi-model probing ({max_models} distinct models in window)")
        if has_enum and max_invoke >= combined_threshold:
            reasons.append(f"enumeration followed by invocation ({max_invoke} calls after model discovery)")
        if reasons:
            flagged.append((identity, reasons, max_invoke, max_models))

    if not flagged:
        return "COMPLIANT", (
            f"No LLM-jacking burst pattern exceeded thresholds across {len(by_identity)} identity(ies) "
            f"and {len(events)} Bedrock-related event(s) analyzed"
        )

    flagged.sort(key=lambda x: (x[2], x[3]), reverse=True)
    shown = flagged[:TOP_FLAGGED_IN_EVIDENCE]
    detail = "; ".join(f"{ident} [{', '.join(reasons)}]" for ident, reasons, _, _ in shown)
    more = f" (+{len(flagged) - TOP_FLAGGED_IN_EVIDENCE} more)" if len(flagged) > TOP_FLAGGED_IN_EVIDENCE else ""
    return "NON_COMPLIANT", (
        f"Potential LLM-jacking pattern detected for {len(flagged)} identity(ies): {detail}{more}. "
        f"Heuristic only - investigate before treating as confirmed; cross-check GuardDuty Bedrock protection findings."
    )


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, account_id, regions, lookback_hours, window_minutes, call_threshold, model_threshold, combined_threshold):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)
    window = timedelta(minutes=window_minutes)

    print(f"\nRegions to Scan: {len(regions)}")
    print(
        f"Lookback: {lookback_hours}h | Window: {window_minutes}m | "
        f"Call threshold: {call_threshold} | Model threshold: {model_threshold} | "
        f"Combined (enum+invoke) threshold: {combined_threshold}\n"
    )

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            ct_client = session.client("cloudtrail", region_name=region)
            events, truncated = fetch_bedrock_events(ct_client, start_time, end_time)
        except (ClientError, EndpointConnectionError) as e:
            reason = classify_error(e)[1] if isinstance(e, ClientError) else "Bedrock/CloudTrail endpoint not available in this region"
            skipped += 1
            results.append({"Region": region, "Status": "SKIPPED", "Evidence": reason})
            continue
        except NoCredentialsError:
            skipped += 1
            results.append({"Region": region, "Status": "SKIPPED", "Evidence": "No valid credentials available"})
            continue

        try:
            status, evidence = evaluate_region_activity(events, window, call_threshold, model_threshold, combined_threshold)
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
    filename = f"cloudtrail_llmjacking_activity_{account_id}_{timestamp}.csv"
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
    parser.add_argument("--call-threshold", type=int, default=100, help="Flag an identity if it makes >= this many Bedrock invocations within the window")
    parser.add_argument("--model-threshold", type=int, default=5, help="Flag an identity if it invokes >= this many distinct models within the window")
    parser.add_argument("--combined-threshold", type=int, default=10, help="Flag an identity if it has both enumeration and >= this many invocations within the window")
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
        args.lookback_hours, args.window_minutes, args.call_threshold, args.model_threshold, args.combined_threshold,
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
    print("GuardDuty Bedrock protection findings before treating as an incident.")


if __name__ == "__main__":
    main()