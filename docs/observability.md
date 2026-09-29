# Task 4 — Observability design

This is the proposed monitoring design for the Task 1 architecture. Task 2 currently provisions the S3/SQS infrastructure; the application instrumentation, dashboards, alarms, EKS and RDS described here are not yet implemented.

## Monitoring and alerting

Use CloudWatch dashboards, metrics and alarms, with structured application logs sent over outbound HTTPS from the on-premise VM and from EKS. Instrument API calls and database operations with OpenTelemetry. Route actionable alarms to the on-call team through SNS and the organisation's incident channel.

**Mode A — API:** measure availability and end-to-end latency from the on-premise client, OAuth token failures, HTTP errors and timeouts. Track ALB/target 5xx errors, unhealthy targets, API pod restarts and database latency/connections. An authenticated synthetic request from on-premise tests the complete path, including DNS, TLS and authentication. Initial alert candidates are three consecutive synthetic failures, or API 5xx rate above 1% / p95 latency above one second for five minutes, with a minimum traffic threshold. Tune these against agreed service targets.

**Mode B — batch:** monitor scheduled-file arrival, upload failures, queue backlog/oldest-message age, worker retries, validation rejections, processing duration and committed/rejected row counts. Page on any visible DLQ message or a batch missing its completion deadline; warn when queue age exceeds ten minutes. An independent scheduled check compares expected nightly batches with the ingestion ledger, so a stopped uploader or an empty queue cannot falsely indicate success. Thresholds and the nightly deadline must be agreed with the data owner. SQS counts are approximate; use `ApproximateNumberOfMessagesVisible` for DLQ alarms and the ledger for business completion.

## Correlation across boundaries

Propagate a request ID and trace context from the VM into API logs and traces. For files, retain a stable batch ID across retries and include it in the server-selected S3 key. The worker recovers that ID from the S3 event and logs the object version, SQS message ID, attempt, stage, duration and outcome. S3 notifications do not automatically carry application trace context. Record batch completion in the same database transaction as the load. Use UTC timestamps and synchronised clocks; keep IDs in logs rather than high-cardinality metric labels. Exclude tokens, presigned URLs and CSV contents; restrict log access and agree retention.

## Runbook — nightly batch missing or failed

1. Identify the batch, expected deadline and last completed stage from the ledger and correlated logs. Acknowledge the alert and notify the data owner of the delay.
2. If no object arrived, check source-file readiness, uploader execution, OAuth, outbound connectivity and URL expiry. If it arrived, verify its exact version, `incoming/` prefix, `.csv` suffix and S3-to-SQS notification permissions.
3. For a backlog or DLQ entry, inspect worker health, IAM/database failures and validation errors. Correct bad input with the data owner. For transient faults, fix the cause before controlled replay; verify the database's batch-ID uniqueness protection first. Never blindly purge queues or re-import committed batches.
4. Confirm one successful database commit, reconcile row counts and verify the backlog clears. Record the cause, recovery and prevention action before closing the incident.
