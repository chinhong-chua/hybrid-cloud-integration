# Task 2 — File ingestion infrastructure

This slice provisions a private, versioned S3 bucket, an SQS ingestion queue, a dead-letter queue (DLQ), and separate IAM policies for the API uploader and ingestion worker. S3 sends notifications only for keys beginning `incoming/` and ending `.csv`. The queue contains an event describing the object, not the CSV itself.

## File guide

- `main.tf`: AWS provider configuration and the reusable module call.
- `variables.tf`: project name, region, environment and bucket-name inputs.
- `versions.tf`: Terraform and AWS provider version constraints.
- `outputs.tf`: names, URLs and IAM policy ARNs needed by future applications.
- `modules/file-ingestion/main.tf`: storage, queues and notification permissions.
- `modules/file-ingestion/iam.tf`: limited application permissions.

## Security and scope

S3 blocks public access and disables object ACLs. SSE-S3 encrypts objects using S3-managed keys; SSE-SQS encrypts queue messages using SQS-owned keys. Resource policies deny non-HTTPS requests. The notification policy allows only this bucket in this AWS account to send messages. Wildcards in explicit **Deny** statements enforce restrictions; they do not grant wildcard access.

The API policy permits `PutObject` under `incoming/`; the worker can read object versions and consume its queue. Policies are created but **not attached**: EKS roles and their trust relationships are outside this slice. The API must enforce each client's subprefix when signing URLs. An IAM policy covering `incoming/*` alone does not enforce client isolation. No permanent AWS keys or OAuth secrets are created.

No EKS, API, uploader, CSV worker, database, alarms or identity provider is deployed. This is the durable handoff layer, not a complete ingestion application. CloudTrail data events, retention policy and production monitoring are follow-up operational work. No automatic object expiry is configured until retention requirements are agreed. Versioned objects therefore continue consuming storage.

## Run locally

The backend now stores state in the separate S3 bucket `hce-dev-446709109300-terraform-state`, at `dev/ingestion.tfstate`, with native locking enabled. Migration from recovered local state completed and the subsequent plan reported no changes. See [Terraform state and team operations](../docs/terraform-state.md) for versioning, updates, recovery, and developer coordination.

For account checks, new-account profiles and SSO/key setup, see [AWS CLI setup](../docs/aws-setup.md).

Use Terraform >= 1.10 and AWS CLI credentials from your normal AWS profile or SSO login. Do not put credentials in `.tfvars`. Commands below run from `infra/` and assume `terraform` is on PATH. The project name defaults to `hybrid-cloud-integration`; override `project_name` in your variable file if needed.

```powershell
aws sts get-caller-identity
# First-time setup only; preserve an existing edited variable file.
if (-not (Test-Path terraform.tfvars)) {
    Copy-Item terraform.tfvars.example terraform.tfvars
}
# Edit terraform.tfvars: choose a globally unique bucket name.
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan '-out=ingestion.tfplan'
terraform show -no-color ingestion.tfplan
```

Deployment is a separate step after reviewing the saved plan and target AWS account:

```powershell
terraform apply ingestion.tfplan
```

`init` downloads providers and prepares the directory. `plan` previews changes; it does not create infrastructure. `apply` executes the saved plan. Commit `.terraform.lock.hcl` to keep provider selection reproducible. Local state backups, plans and private variable files are ignored by Git. Shared S3 state and locking are configured; CI activation still requires the setup described in the state operations guide.

Choose the AWS account/profile deliberately. The deploying identity needs provisioning permissions for these S3, SQS and IAM resources; application policies are not deployment policies. Resources may incur charges depending on account eligibility and usage: having a free-tier account does not guarantee a zero bill.

## Smoke check after deployment

Using your authorised test identity, create a small CSV and upload it. The production presigned-URL API is not part of this check.

```powershell
'transaction_id,amount' | Set-Content -Encoding ascii sample.csv
'demo-001,10.00' | Add-Content -Encoding ascii sample.csv
$inputBucket = terraform output -raw bucket_name
$ingestionQueue = terraform output -raw queue_url
aws s3 cp sample.csv "s3://$inputBucket/incoming/sample.csv"
aws sqs receive-message --queue-url $ingestionQueue --wait-time-seconds 20 --max-number-of-messages 10
```

Confirm an `ObjectCreated` event contains `incoming/sample.csv` and a version ID. S3 may also publish an initial `s3:TestEvent`; receiving that alone does not prove the upload worked. Poll again if needed. Uploading outside `incoming/` or using a non-`.csv` suffix should produce no corresponding object notification. Existing messages can still be returned. Notifications are asynchronous and can be duplicated or out of order.

The visibility timeout is five minutes; the future worker must extend it during longer jobs. After five unsuccessful receives, messages become eligible for the DLQ. This is driven by consumer receives, not a timer: without a worker, messages remain in the source queue until its four-day retention expires. DLQ retention is fourteen days. The worker must handle duplicate batches transactionally and delete messages only after recording their outcome.

## Cleanup

Review `terraform plan -destroy` before running `terraform destroy`. The bucket deliberately has `force_destroy = false`: Terraform refuses to delete it while objects or versions remain. Explicitly remove disposable test objects, all their versions and delete markers before destroying. Do not use this process on retained business data.
