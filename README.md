# Hybrid Cloud Integration

An AWS hybrid integration design connecting a legacy on-premise application to a cloud microservice on Kubernetes. It supports on-demand reference-data API calls and nightly CSV transaction imports, with encrypted transport, authenticated access and an end-to-end observability design.

The repository includes the architecture, a Terraform slice for the S3/SQS file handoff, an approval-gated GitHub Actions pipeline, operational and security guidance, and a Python configuration-change risk detector.

## Start here

Read the [architecture](architecture/README.md) for the complete design and trade-offs, then the [infrastructure guide](infra/README.md) for the implemented slice. Review the [pipeline](.github/workflows/terraform.yml) and [risk detector](drift-detector/README.md) together to follow a change from source review to deployment.

| Task | Where to look | What it covers |
| --- | --- | --- |
| 1 - Architecture | [Design write-up](architecture/README.md) and [editable Draw.io diagram](architecture/task-1-architecture.drawio) | Both integration modes, connectivity, authentication boundaries and trade-offs. The write-up also contains a Mermaid diagram. |
| 2 - Infrastructure as code | [Infrastructure guide](infra/README.md) and [file-ingestion module](infra/modules/file-ingestion/) | S3, SQS, dead-letter queue, IAM policies, deployment commands and smoke checks. |
| 3 - CI/CD | [Terraform workflow](.github/workflows/terraform.yml) and [TFLint configuration](.tflint.hcl) | Static checks, source-risk assessment, saved plans and approved apply. Pipeline decisions are summarised below. |
| 4 - Observability | [Monitoring and recovery runbook](docs/observability.md) | API and batch signals, cross-boundary correlation and failed nightly transfer recovery. |
| 5 - Security | [Security considerations](docs/security.md) | Three principal risks and the implemented or proposed controls for each. |
| 6 - Configuration risk detection | [Detector guide](drift-detector/README.md), [script](drift-detector/detector.py), [fixtures](drift-detector/fixtures/) and [tests](drift-detector/test_detector.py) | Rule-based Git diff analysis, JSON findings, risk levels and CI failure behaviour. |

## Integration overview

- **Mode A - Real-time API:** the on-premise VM obtains an OAuth access token and calls the public Application Load Balancer over HTTPS. The ALB forwards HTTPS to an API on private EKS nodes; the API validates the JWT and required scope before returning reference data.
- **Mode B - Nightly batch:** the uploader requests a scoped presigned URL from the authenticated API and uploads a CSV to private S3. S3 sends an object-created event to SQS. An EKS worker reads the object version, validates and deduplicates the batch, and loads private RDS PostgreSQL over TLS. Repeated processing failures go to a dead-letter queue.

The on-premise system initiates outbound HTTPS connections; no inbound internet access to the data centre is required. The design assumes an organisation-managed OAuth identity provider and permission to use authenticated public endpoints. The architecture guide discusses VPN connectivity if private access is required.

## Implementation scope and verification

Terraform implements the durable file handoff: a private, versioned S3 bucket with SSE-S3 encryption and HTTPS-only access; encrypted SQS ingestion and dead-letter queues; notifications for keys beginning `incoming/` and ending `.csv`; and separate uploader and worker IAM policies. Terraform state uses a separate S3 backend with native locking.

EKS, ALB, the identity provider, API and uploader code, CSV processing, RDS, and application monitoring remain design components. The application IAM policies are created but are not attached to workload roles. The observability and security documents explain the controls needed to complete the system.

Recorded verification includes deployment of the Terraform slice, migration to S3 state followed by a no-change plan, and a GitHub Actions checks/plan/approved-apply run reporting **0 added, 0 changed, 0 destroyed**. The detector has 30 locally passing tests and has been integrated into the workflow; hosted execution of the Task 6 gate has not yet been verified. A complete application-level upload-to-database flow has not been demonstrated.

## CI/CD design

The [workflow](.github/workflows/terraform.yml) runs `checks` and `risk_check` in parallel. Both must pass before `plan`; `apply` then waits for approval through the GitHub `dev` environment.

1. **Validate and assess risk:** Terraform formatting, validation and TFLint check the configuration. The Python detector runs its tests and compares source revisions, producing a JSON risk report. High findings or scan errors block plan; medium findings still need human review. Pull requests run these jobs without AWS credentials.
2. **Plan on main:** pushes and manual runs on `main` use GitHub OIDC to assume a dedicated AWS plan role. Terraform saves both a binary `tfplan` and readable `plan.txt` as an artifact for review. A precheck verifies that the `dev` environment has a required reviewer.
3. **Approve and apply:** after environment approval, a separate apply role executes the same run's saved plan. S3 state locking and workflow concurrency coordinate deployments. Artifacts expire after one day, and actions are pinned to commit SHAs.

OIDC provides temporary AWS credentials without stored AWS access keys. Setup requires repository variables `AWS_REGION`, `TF_STATE_BUCKET`, `AWS_PLAN_ROLE_ARN`, `AWS_APPLY_ROLE_ARN` and `INGESTION_BUCKET_NAME`, plus a protected `dev` environment with required reviewers and a main-only deployment rule.

The detector assesses source changes before plan, so it uses Git diffs rather than plan JSON. Its deterministic rules cover public ingress, wildcard IAM permissions, removed encryption and network rule changes. It does not query live AWS drift or evaluate all Terraform expressions; review its findings alongside the Terraform plan. No LLM service is required.

**Extending to staging and production:** reuse the ingestion module with separate environment inputs, state keys or buckets, OIDC roles and GitHub environments, preferably in separate AWS accounts. Parameterise the current `dev` values in the workflow and backend configuration. Give each environment its own concurrency group, plan artifact and approval gate, with stricter production reviewers. Promote the reviewed source revision and generate a fresh plan against each environment's state.

## Run local checks

Run these commands from the repository root in PowerShell. Terraform requires version `>= 1.10, < 2.0`; CI pins its version in the workflow. Provider installation requires network access, but these validation commands do not require AWS credentials or initialise the remote backend.

```powershell
terraform fmt -check -recursive
terraform -chdir=infra init -backend=false -lockfile=readonly
terraform -chdir=infra validate
```

With Python 3.10 or newer, test and demonstrate the detector without AWS access:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r drift-detector/requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s drift-detector -p 'test_*.py' -v
.\.venv\Scripts\python.exe drift-detector/detector.py --diff drift-detector/fixtures/public-ingress.diff
```

The final command prints a JSON report and intentionally exits with code `1` because the fixture introduces public ingress. See the [detector guide](drift-detector/README.md) for comparison options, other fixtures and limitations.

For an authenticated plan, deployment, smoke check or cleanup, follow the [infrastructure guide](infra/README.md). The [backend configuration](infra/backend.tf) targets the existing dev deployment; when using another account, supply your own backend settings and a globally unique ingestion bucket name using the [backend example](infra/backend.hcl.example) and [variable example](infra/terraform.tfvars.example).
