"""Keep one CloudTrail trail logging. Invoked in two ways.

1. By an EventBridge rule that matches the CloudTrail record of a StopLogging call. The record
   arrives under event["detail"]. This is the fast path: the trail is back within seconds - when the
   event arrives. In six trials on 2026-11-18 it arrived four times.
2. On a schedule, with the input {"check": "scheduled"}. This is the backstop, and it does not
   depend on any event: it asks whether the trail is logging and restarts it if it is not.

Either way the function acts on the trail named in the TRAIL_NAME environment variable and writes
one JSON line to its log, with the times needed to measure how long the trail was off.

It deliberately does little:
  - it acts only on the one trail it is configured for;
  - it ignores a StopLogging call that failed, because a failed call stopped nothing;
  - it logs no identities, addresses or account IDs - those stay in CloudTrail, where they belong.

The execution role allows cloudtrail:GetTrailStatus and cloudtrail:StartLogging on that one trail
and nothing else in CloudTrail, so a bug here cannot stop or change a trail.
"""
import json
import os
from datetime import datetime, timezone

import boto3

TRAIL_NAME = os.environ["TRAIL_NAME"]
cloudtrail = boto3.client("cloudtrail")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log(**fields):
    print(json.dumps(fields))


def scheduled_check(received):
    status = cloudtrail.get_trail_status(Name=TRAIL_NAME)
    if status["IsLogging"]:
        log(action="checked", is_logging=True, function_received=received)
        return {"action": "checked"}
    stopped = status.get("StopLoggingTime")
    cloudtrail.start_logging(Name=TRAIL_NAME)
    log(action="restarted_by_schedule", trail=TRAIL_NAME,
        trail_stopped=stopped.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if stopped else None,
        function_received=received, start_logging_returned=now())
    return {"action": "restarted_by_schedule"}


def handler(event, context):
    received = now()
    if event.get("check") == "scheduled":
        return scheduled_check(received)

    detail = event.get("detail", {})
    base = {"cloudtrail_event_id": detail.get("eventID"), "stop_call_time": detail.get("eventTime"),
            "function_received": received}

    # The caller may have passed the trail's name or its full ARN.
    requested = (detail.get("requestParameters") or {}).get("name", "")
    if requested != TRAIL_NAME and not requested.endswith(f":trail/{TRAIL_NAME}"):
        log(action="skipped", reason="the call was for a different trail", **base)
        return {"action": "skipped"}

    if detail.get("errorCode"):
        log(action="skipped", reason="the StopLogging call failed, so nothing was stopped",
            error_code=detail["errorCode"], **base)
        return {"action": "skipped"}

    cloudtrail.start_logging(Name=TRAIL_NAME)
    log(action="restarted", trail=TRAIL_NAME, start_logging_returned=now(), **base)
    return {"action": "restarted"}
