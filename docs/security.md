# Task 5 — Security considerations

The following three risks apply to the proposed hybrid integration. Task 2 implements the S3/SQS controls and application IAM policies; application enforcement, EKS role bindings, ALB and RDS controls remain design work.

## 1. Stolen credentials or upload URLs allow impersonation

A compromised on-premise OAuth secret could let an attacker call the API or request upload URLs. Store it in the organisation's secret store, accessible only to the application identity, and rotate it. Use short-lived access tokens; the API validates the signature, allowed algorithm, issuer, audience, expiry and the required `reference:read` or `batch:upload` scope. Alert on unusual authentication failures and upload activity.

The API signs uploads using temporary credentials from its dedicated EKS workload role. Generate short-lived URLs for an exact server-selected object key and exclude tokens and URLs from logs. Presigned URLs are bearer credentials and remain reusable until expiry; they are not one-time tokens. GitHub deployment authentication already uses OIDC and separate plan/apply roles, avoiding stored AWS access keys.

## 2. Excessive permissions or exposed paths disclose client data

The API must derive each client's upload prefix from the authenticated identity, rather than trust a caller-supplied path. The current `incoming/*` uploader policy alone does not enforce client isolation. Bind separate API and worker IAM roles to their respective Kubernetes service accounts: the API may upload; the worker may read input versions and consume its queue. Restrict S3 publishing to the designated SQS queue using the source bucket ARN and account. Keep S3 public access blocked and ACLs disabled.

Use certificate-validated HTTPS from on-premise to the identity provider, ALB and S3. ACM manages the ALB's public certificate. Forward HTTPS to private API targets and restrict ingress to the ALB security group; ALB does not validate target certificates, so this is not mutual TLS. The worker verifies the RDS certificate and uses a restricted database user whose credentials are held in Secrets Manager. Task 2 uses SSE-S3 and SSE-SQS, with keys managed by AWS; bucket and queue policies deny non-TLS requests. 

## 3. Malicious or repeated files corrupt data or exhaust processing

Treat authenticated uploads as untrusted input. Enforce file-size, row-count and field-length limits, validate schema and business rules, and use parameterised database operations. Check the event's expected bucket/prefix and read the exact S3 object version. Bound worker concurrency and processing time so oversized or malformed files cannot monopolise capacity.

Enforce uniqueness on the client and stable batch ID in the same transaction as the import. A retry or duplicate message then cannot import a committed batch twice. Reject invalid files with a recorded reason; retry transient failures and investigate exhausted retries in the DLQ. Delete the queue message only after a committed load or recorded rejection. Controlled replay must check the batch ledger first.
