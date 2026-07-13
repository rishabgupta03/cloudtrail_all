#!/usr/bin/env python3
"""
Control : No potential privilege escalation activity detected in CloudTrail

Logic   :
  Scan CloudTrail lookup_events (last 90 days) across all enabled regions
  for IAM API calls that are known privilege escalation vectors.

  For each region:
    - Query each suspicious event name via lookup_events (one at a time —
      AWS API limitation: only one LookupAttribute per call)
    - Collect all matching events with caller identity and time
    - If ZERO suspicious events found → COMPLIANT
    - If ANY suspicious events found  → NON_COMPLIANT

  Important AWS API constraints handled in this script:
    1. lookup_events only covers the last 90 days (hard AWS limit)
    2. Rate limit: 2 requests/second/region — sleep between calls
    3. Only ONE LookupAttribute allowed per call — loop per event name
    4. CloudTrail is regional — must query each region separately

  Privilege escalation event names monitored (IAM + STS):
    Policy manipulation : CreatePolicyVersion, SetDefaultPolicyVersion,
                          PutUserPolicy, PutRolePolicy, PutGroupPolicy,
                          AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy,
                          DeleteUserPolicy, DeleteRolePolicy
    Identity creation   : CreateUser, CreateRole, CreateAccessKey,
                          CreateLoginProfile, UpdateLoginProfile
    Role assumption     : AssumeRole, UpdateAssumeRolePolicy
    Group membership    : AddUserToGroup
    Password/key ops    : UpdateAccessKey, CreateVirtualMFADevice,
                          DeactivateMFADevice, DeleteVirtualMFADevice
    Compute escalation  : PassRole (via EC2/Lambda — logged as RunInstances,
                          CreateFunction, UpdateFunctionCode, AddPermission)
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError
from tqdm import tqdm

CONTROL_NAME   = "No potential privilege escalation activity detected in CloudTrail"
LOOKBACK_DAYS  = 90    # AWS hard limit for lookup_events
RATE_SLEEP     = 0.6   # seconds between lookup_events calls (stay under 2/sec limit)

# ── Privilege escalation event names to scan ──────────────────────────
PRIV_ESC_EVENTS = [
    # Direct IAM policy manipulation
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "DeleteUserPolicy",
    "DeleteRolePolicy",
    # Identity / credential creation
    "CreateUser",
    "CreateRole",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    # Role assumption and trust policy
    "AssumeRole",
    "UpdateAssumeRolePolicy",
    # Group membership changes
    "AddUserToGroup",
    # MFA / key manipulation
    "UpdateAccessKey",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
    # Compute-based escalation paths
    "RunInstances",          # can attach IAM instance profile
    "CreateFunction",        # Lambda with privileged execution role
    "UpdateFunctionCode",    # inject malicious code into existing Lambda
    "AddPermission",         # grant external invocation rights on Lambda
]


# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base  = boto3.Session()
        creds = base.client("sts").assume_role(
            RoleArn=role_arn, RoleSessionName="control-audit"
        )["Credentials"]
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
    return [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=True)["Regions"]
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


# ==================================================
# HELPERS
# ==================================================
def lookup_events_for_name(ct_client, event_name, start_time, end_time):
    """
    Paginate lookup_events for a single event name.
    Returns list of matching event dicts.
    Handles throttling with retry.
    """
    events    = []
    kwargs    = {
        "LookupAttributes": [
            {"AttributeKey": "EventName", "AttributeValue": event_name}
        ],
        "StartTime":  start_time,
        "EndTime":    end_time,
        "MaxResults": 50,
    }

    while True:
        try:
            resp = ct_client.lookup_events(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ThrottlingException":
                time.sleep(2)
                try:
                    resp = ct_client.lookup_events(**kwargs)
                except ClientError:
                    break
            else:
                raise
        events.extend(resp.get("Events", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
        time.sleep(RATE_SLEEP)   # respect 2 req/sec rate limit

    return events


def parse_caller(ct_event_json):
    """
    Extract caller identity from the raw CloudTrail JSON string.
    Returns a human-readable string.
    """
    try:
        detail   = json.loads(ct_event_json)
        identity = detail.get("userIdentity", {})
        id_type  = identity.get("type", "Unknown")
        arn      = identity.get("arn", "")
        username = identity.get("userName", "")
        caller   = arn or username or id_type
        src_ip   = detail.get("sourceIPAddress", "N/A")
        return f"{caller} from {src_ip}"
    except Exception:
        return "Unknown caller"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id    = get_account_id(session)
    regions       = get_regions(session)
    results       = []
    total_checked = compliant = non_compliant = skipped = 0

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=LOOKBACK_DAYS)

    print(f"\nRegions to scan : {len(regions)}")
    print(f"Lookback window : last {LOOKBACK_DAYS} days "
          f"({start_time.strftime('%Y-%m-%d')} → "
          f"{end_time.strftime('%Y-%m-%d')})")
    print(f"Event names     : {len(PRIV_ESC_EVENTS)}\n")

    for region in tqdm(regions, desc="Scanning regions"):
        try:
            ct = session.client("cloudtrail", region_name=region)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            skipped += 1
            results.append(_row(
                account_id, region, "N/A", "N/A",
                "N/A", "N/A", "SKIPPED",
                f"Region access failed: {code}",
            ))
            continue

        region_findings = []   # suspicious events found in this region

        for event_name in tqdm(
            PRIV_ESC_EVENTS, desc=f"  {region}", leave=False
        ):
            try:
                events = lookup_events_for_name(
                    ct, event_name, start_time, end_time)
                for ev in events:
                    region_findings.append({
                        "event_name": event_name,
                        "event_time": ev.get("EventTime", ""),
                        "event_id":   ev.get("EventId", "N/A"),
                        "username":   ev.get("Username", "N/A"),
                        "caller":     parse_caller(
                            ev.get("CloudTrailEvent", "{}")),
                    })
                time.sleep(RATE_SLEEP)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDeniedException", "UnauthorizedOperation",
                            "AuthFailure"):
                    # Can't read CloudTrail in this region
                    skipped += 1
                    results.append(_row(
                        account_id, region, "N/A", "N/A",
                        "N/A", "N/A", "SKIPPED",
                        f"Access denied reading CloudTrail for "
                        f"event '{event_name}': {code}",
                    ))
                    break   # skip remaining events for this region
                # For other errors, continue to next event name
                continue

        # ── Evaluate region findings ───────────────────────────────────
        total_checked += 1

        if not region_findings:
            compliant += 1
            results.append(_row(
                account_id, region,
                "No suspicious events",
                f"arn:aws:cloudtrail:{region}:{account_id}:trail/*",
                str(len(PRIV_ESC_EVENTS)),
                "0",
                "COMPLIANT",
                f"No privilege escalation activity detected in the last "
                f"{LOOKBACK_DAYS} days across all {len(PRIV_ESC_EVENTS)} "
                "monitored event names.",
            ))
        else:
            non_compliant += 1
            # Build a concise summary of what was found
            event_summary = {}
            for f in region_findings:
                event_summary.setdefault(f["event_name"], []).append(
                    f["username"]
                )
            summary_parts = [
                f"{name}({len(users)}x by: "
                f"{', '.join(set(users))[:80]})"
                for name, users in event_summary.items()
            ]
            results.append(_row(
                account_id, region,
                "; ".join(summary_parts[:5]),   # first 5 event types
                f"arn:aws:cloudtrail:{region}:{account_id}:trail/*",
                str(len(PRIV_ESC_EVENTS)),
                str(len(region_findings)),
                "NON_COMPLIANT",
                f"{len(region_findings)} potential privilege escalation "
                f"event(s) detected in the last {LOOKBACK_DAYS} days: "
                + "; ".join(summary_parts),
            ))

    return results, total_checked, compliant, non_compliant, skipped


def _row(account, region, events_found, resource_arn,
         events_checked, event_count, status, evidence):
    return {
        "Account":          account,
        "Region":           region,
        "SuspiciousEvents": events_found,
        "ResourceArn":      resource_arn,
        "EventsMonitored":  events_checked,
        "FindingCount":     event_count,
        "Status":           status,
        "Evidence":         evidence,
    }


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename   = f"cloudtrail_no_privilege_escalation_{account_id}.csv"
    fieldnames = [
        "Account", "Region", "SuspiciousEvents", "ResourceArn",
        "EventsMonitored", "FindingCount", "Status", "Evidence",
    ]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check: No privilege escalation activity in CloudTrail"
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume")
    args = parser.parse_args()

    session    = get_session(args.role_arn)
    account_id = get_account_id(session)

    print("=" * 60)
    print(f"  CONTROL : {CONTROL_NAME}")
    print(f"  ACCOUNT : {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = \
        check_control(session)

    overall  = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    filename = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print(f"  CONTROL        : {CONTROL_NAME}")
    print(f"  ACCOUNT        : {account_id}")
    print(f"  TOTAL CHECKED  : {total_checked}  (regions)")
    print(f"  COMPLIANT      : {compliant}")
    print(f"  NON-COMPLIANT  : {non_compliant}")
    print(f"  SKIPPED        : {skipped}")
    print(f"  OVERALL STATUS : {overall}")
    print(f"  CSV GENERATED  : {filename}")
    print("=" * 60)

    sys.exit(0 if overall == "COMPLIANT" else 1)


if __name__ == "__main__":
    main()