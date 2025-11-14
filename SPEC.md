# SPEC: Control Tower / Landing Zone-Oriented HIPAA-Aware AWS Org Baseline

## 1. Purpose and Scope

This repository defines a **Control Tower / Landing Zone**–oriented implementation
of a HIPAA-aware AWS Organizations baseline suitable for small scientific /
research startups.

It mirrors the security model of the SuperWerker-oriented repo, but assumes:

- AWS Control Tower is the primary landing zone mechanism.
- Customizations (SCPs, guardrails, StackSets) are managed here.

It provides a phased security profile for Organizational Units (OUs):

- `Workloads_Prod` – strongly governed, preventive-heavy
- `Workloads_Test` – detection-first, with selective auto-remediation
- `Sandbox` – notify-only with a minimal non-negotiable baseline

This repo:

- Does **not** contain client secrets or PHI.
- Is intended to be instantiated per client (via GitHub template) with
  client-specific configuration.
- Assumes Terraform or CDK for infra, but the design is IaC-agnostic.

Non-goals:

- Application/workload business logic.
- Full greenfield Control Tower bootstrap beyond what is needed for this pattern.
- Detailed PHI policy text (we only supply technical hooks and zones).

---

## 2. Control Model

### 2.1 Control Types

We use AWS-native terms plus one extra bucket:

- **Advisory**  
  Human guidance in docs/runbooks. No technical enforcement.

- **Preventive**  
  Implemented with **SCPs**, org policies, and **Control Tower preventive guardrails**.  
  Blocks non-compliant actions.

- **Detective**  
  Implemented with **AWS Config rules** and **Security Hub** controls.  
  Produces findings/alerts, no direct changes.

- **Reactive**  
  Implemented with **SSM Automation**, **Lambda**, or **EventBridge**.  
  Automatically remediates selected findings.

- **Proactive**  
  Implemented with **Control Tower proactive controls** (CloudFormation hooks)  
  for CloudFormation/IaC-driven resources.

Each control in code should be annotated (comment or metadata) with its type(s).

### 2.2 OU Posture

We assume at least these OUs under the Control Tower root:

- `Workloads_Prod`
  - Default: **Preventive + Detective**, with selective **Reactive** and **Proactive** controls.
  - Intended for production workloads, including those that may touch PHI.

- `Workloads_Test`
  - Default: **Detective-first**, with minimal **Preventive** controls that are cheap,
    safe, and broadly applicable (e.g., IMDSv2, S3 Block Public Access).
  - Selected **Reactive** controls for high-risk misconfigurations (public S3, etc.).

- `Sandbox`
  - Default: **Detective / notify-only** for most controls.
  - Minimal **Preventive** baseline:
    - CloudTrail / Config / GuardDuty / Security Hub
    - S3 Block Public Access
    - IMDSv2 recommended (configurable)

Behavior differences between OUs must be explicit in both code and docs.

---

## 3. Assumptions and Dependencies

- AWS Control Tower is or will be deployed in the management account:
  - Management, Log Archive, and Security/Audit accounts exist.
  - Control Tower core governance is operational.

- This repo is responsible for:
  - Defining / validating OUs.
  - Defining and attaching SCPs.
  - Defining **Control Tower customizations**:
    - Preventive and detective guardrails (StackSets).
    - Proactive controls where applicable.
  - Setting up:
    - Config aggregator in Security account.
    - Security Hub and GuardDuty delegated admins + auto-enablement.

- GitHub is used for CI/CD; AWS access uses OIDC + IAM roles.
- IaC tooling:
  - Terraform or CDK is acceptable, but this spec will assume Terraform-style layout.

---

## 4. Repository Structure

High-level layout:

    .
    ├── README.md
    ├── SPEC.md                  # This file
    ├── profiles/
    │   ├── hipaa-small-startup-phase1.yaml
    │   ├── hipaa-small-startup-phase2.yaml
    │   └── hipaa-small-startup-phase3.yaml
    ├── config/
    │   ├── project-metadata.example.yaml
    │   ├── org-structure.example.yaml
    │   └── controls.example.yaml
    ├── infra/
    │   ├── landing-zone/
    │   │   ├── main.tf
    │   │   ├── variables.tf
    │   │   ├── outputs.tf
    │   │   ├── scp/
    │   │   │   ├── imdsv2-required.json
    │   │   │   ├── s3-bap-protect.json
    │   │   │   ├── core-encryption-s3.json
    │   │   │   ├── core-encryption-ebs.json
    │   │   │   ├── core-encryption-rds.json
    │   │   │   └── core-encryption-dynamodb.json
    │   │   ├── ct-customizations/
    │   │   │   ├── guardrails/
    │   │   │   └── proactive-controls/
    │   │   └── modules/
    │   ├── security-hub/
    │   ├── config-rules/
    │   └── backups/
    └── .github/
        └── workflows/
            ├── 01-validate.yaml
            ├── 02-deploy-landingzone-phase1.yaml
            ├── 03-deploy-landingzone-phase2.yaml
            └── 04-deploy-landingzone-phase3.yaml

- `profiles/` – default control sets for each phase.
- `config/` – per-client metadata and control overrides.
- `infra/landing-zone/` – Control Tower customizations, SCPs, guardrails.
- `infra/security-hub/` – Security Hub and standards configuration.
- `infra/config-rules/` – org-level Config rules and aggregators.
- `infra/backups/` – optional backup plans and policies.
- `.github/workflows/` – CI/CD workflows.

---

## 5. Configuration Model

### 5.1 Project Metadata

File: `config/project-metadata.example.yaml`

    project_id: CLIENT-YYYY-AWSORG-HIPAA
    client_name: Example Scientific Co
    deployment_engine: landingzone
    security_profile: hipaa-small-startup
    security_phase: 1          # 1, 2, or 3
    ct_region: us-east-1
    regions:
      - us-east-1
      - us-west-2

Developers:

- Copy to `config/project-metadata.yaml`.
- Update for the client and landing zone region.

### 5.2 Org Structure

File: `config/org-structure.example.yaml`

    root_ou: /CLIENT
    organizational_units:
      - name: Workloads_Prod
        path: /CLIENT/Workloads_Prod
      - name: Workloads_Test
        path: /CLIENT/Workloads_Test
      - name: Sandbox
        path: /CLIENT/Sandbox
      - name: Security
        path: /CLIENT/Security
    accounts:
      - name: LogArchive
        email_alias: aws-logarchive
        ou: /CLIENT/Security
      - name: Security
        email_alias: aws-security
        ou: /CLIENT/Security
      - name: WorkloadsProd
        email_alias: aws-workloads-prod
        ou: /CLIENT/Workloads_Prod
      - name: WorkloadsTest
        email_alias: aws-workloads-test
        ou: /CLIENT/Workloads_Test
      - name: SandboxShared
        email_alias: aws-sandbox
        ou: /CLIENT/Sandbox

This must align with Control Tower Account Factory usage and OU structure.

### 5.3 Controls Profile

File: `config/controls.example.yaml`

    phase: 1

    controls:
      # Logging / detection
      org_cloudtrail_multi_region: true
      org_config_enabled: true
      guardduty_enabled: true
      securityhub_enabled: true

      # S3
      s3_block_public_access_account_level: true
      s3_require_kms_for_sensitive_buckets: true
      s3_tls_only: true
      s3_versioning_detect_only: true

      # Compute
      ec2_require_imdsv2: true
      ec2_default_ebs_encryption: true

      # Datastores
      rds_encryption_required: true
      dynamodb_encryption_required: true

      # PHI / zoning (Phase 3)
      phi_zones_enabled: false
      phi_ou_paths: []

`profiles/hipaa-small-startup-phase{1,2,3}.yaml` define default values for
`controls.*` which `controls.yaml` can override.

---

## 6. Landing Zone Architecture

### 6.1 Core Accounts and OUs

This repo must ensure:

- Core accounts:
  - Management (pre-existing).
  - Log Archive.
  - Security/Audit.
  - Workloads Prod.
  - Workloads Test.
  - Sandbox.

- OUs:
  - `/CLIENT/Workloads_Prod`
  - `/CLIENT/Workloads_Test`
  - `/CLIENT/Sandbox`
  - `/CLIENT/Security`

Creation/registration of accounts may be handled by:

- Control Tower Account Factory invoked manually, or
- IaC integration (if permitted) via Account Factory APIs.

The repo’s Terraform should:

- Create OUs if they do not exist.
- Register accounts with Control Tower if necessary (optional, depending on
  operating model).
- Enroll accounts into governance if not already enrolled.

---

## 7. Controls (Landing Zone Path)

The effective behavior should match the SuperWerker-oriented spec. This section
focuses on how it is implemented using Control Tower and its customization
mechanisms.

### 7.1 Logging and Detection

**Requirements**

- Org-level, multi-account, multi-region CloudTrail sending to Log Archive, with KMS.
- AWS Config enabled across all governed accounts/regions.
- Security Hub and GuardDuty:
  - Delegated admin = Security account.
  - Auto-enable for new accounts.
- Config aggregator in Security account aggregating all member accounts/regions.

**Implementation**

- Preventive / Proactive:
  - Use Control Tower’s baseline landing zone to:
    - Create key accounts and initial governance.
    - Ensure CloudTrail and Config are configured as recommended.
  - Terraform in `infra/landing-zone`:
    - Validates existence and configuration of:
      - CloudTrail (org, multi-region, log archive bucket, KMS).
      - Config recorders per region.
      - Security Hub and GuardDuty delegated admins.
    - Creates or configures a Config aggregator in the Security account.

- Detective:
  - `infra/security-hub`:
    - Enable AWS Foundational Security Best Practices standard org-wide.
    - Enable selected additional standards per controls profile.

- Reactive (Phase 2/3):
  - EventBridge rules in Security account:
    - Trigger SSM Automation or Lambda for selected critical findings
      (e.g., public S3 in `Workloads_Prod`, unencrypted RDS).

**Error Handling**

- If Control Tower baseline is missing or misconfigured:
  - Terraform must fail with a clear error message.
- This repo assumes Control Tower health is managed outside.

---

### 7.2 S3 Block Public Access and Versioning

**Requirements**

- S3 Block Public Access (BAP) must be enabled at account level in all accounts.
- Only designated security-admin roles may change account-level BAP.
- S3 versioning:
  - Detect-only; not strictly enforced.
  - PHI/critical buckets are expected to use versioning (documented).

**Implementation**

- Preventive:
  - StackSet / Terraform module:
    - For each governed account, create `AWS::S3::AccountPublicAccessBlock`
      with all four flags set to `true`.
  - SCP `s3-bap-protect.json`:
    - Deny `s3:PutAccountPublicAccessBlock` unless `aws:PrincipalArn` matches
      a security-admin role pattern.
  - Attach SCP to all relevant OUs (`Workloads_Prod`, `Workloads_Test`, `Sandbox`, `Security`).

- Detective:
  - Control Tower detective guardrail (if available) or custom Config rule:
    - Detect when account-level BAP is disabled.
  - Security Hub:
    - Enable S3 controls (public ACLs, policies, SSL requirements).
  - Config rule for S3 versioning:
    - Buckets without versioning flagged as “warning” or “info”.

- Reactive (Phase 2/3):
  - For `Workloads_Prod`:
    - Lambda or SSM Automation triggered via EventBridge to:
      - Re-enable BAP if disabled.
      - Remove public ACLs/policies from non-whitelisted buckets.
  - For `Workloads_Test`:
    - Remediation on-demand or limited to specific tags.
  - For `Sandbox`:
    - Notify-only; no auto-remediation.

**OU Behavior**

- `Workloads_Prod`:
  - Strict: BAP must remain enabled; reactive remediation recommended.
- `Workloads_Test`:
  - Strict BAP; more flexible remediation policy.
- `Sandbox`:
  - Strict BAP (to avoid accidental internet exposure), but otherwise notify-only.

---

### 7.3 IMDSv2 and EC2

**Requirements**

- IMDSv2 must be enforced for EC2 instances in:
  - `Workloads_Prod` and `Workloads_Test` (mandatory).
- `Sandbox`:
  - IMDSv2 required by default but can be configured off if needed.

**Implementation**

- Preventive:
  - SCP `imdsv2-required.json`:
    - Deny `ec2:RunInstances` where `ec2:MetadataHttpTokens != "required"`.
    - Deny `ec2:ModifyInstanceMetadataOptions` where target tokens != "required".
  - Attach SCP:
    - Always to `Workloads_Prod` and `Workloads_Test`.
    - To `Sandbox` when `controls.ec2_require_imdsv2` is true.

- Proactive:
  - Optional CloudFormation hook (proactive control):
    - Rejects EC2 instance resources not using IMDSv2.
    - Deployed via CT customizations for stacks in `Workloads_Prod` and `Workloads_Test`.

- Detective:
  - Security Hub EC2.8.
  - Config custom rule for IMDSv2 (if not covered by a managed rule).

- Reactive (Phase 2+):
  - SSM Automation document:
    - Updates EC2 instances to IMDSv2 where compatible.
  - Behavior:
    - `Workloads_Prod`: auto-run for non-compliant instances.
    - `Workloads_Test`: exposed as an on-demand runbook.
    - `Sandbox`: disabled by default.

---

### 7.4 Core Encryption Pack (At Rest)

**Scope**

- S3 (for sensitive buckets).
- EBS.
- RDS.
- DynamoDB.

**Requirements**

- S3:
  - SSE-KMS required for designated “sensitive” buckets (logs, PHI, core data).
- EBS:
  - Default EBS encryption = true for all accounts.
  - Unencrypted volumes not allowed in `Workloads_Prod`.
- RDS:
  - All RDS instances/clusters encrypted at rest.
- DynamoDB:
  - Encryption at rest required.

**Implementation**

- Preventive / Proactive:
  - CT managed and custom proactive controls:
    - For CloudFormation-created resources, ensure:
      - EBS volumes and launch templates specify encryption.
      - RDS resources specify encryption.
      - DynamoDB tables specify encryption.
  - Terraform/StackSets:
    - Enable EBS default encryption in each account.
    - Provision KMS keys:
      - Logs key per environment.
      - Data keys per environment or domain.

- Detective:
  - Security Hub controls for S3, EBS, RDS, DynamoDB encryption.
  - CT detective guardrails where available.

- OU Behavior:
  - `Workloads_Prod`:
    - Non-negotiable: all core data stores must be encrypted at rest.
  - `Workloads_Test`:
    - Same defaults; exceptions can be granted but must be explicit.
  - `Sandbox`:
    - Default encryption expected; findings treated as advisory unless overridden.

---

### 7.5 In-Transit Encryption Pack

**Phase 1 (Minimal)**

- Preventive:
  - SCP enforcing S3 TLS-only:
    - Deny S3 requests where `aws:SecureTransport = false`.

- Detective:
  - Security Hub control for S3 SSL requirement.

**Phase 2 (Service Pack A)**

Applied mainly to `Workloads_Prod` (detect-only in `Workloads_Test`):

- API Gateway:
  - Enforce HTTPS/TLS-only endpoints.
  - Require encryption for API cache data (if used).
- ElastiCache (Redis):
  - In-transit and at-rest encryption required.
- RDS:
  - Enforce TLS usage via DB parameter groups and/or RDS Proxy settings.

Implementation:

- Preventive / Proactive:
  - CT custom guardrails / hooks for API Gateway, ElastiCache, RDS.  
- Detective:
  - Security Hub controls for:
    - API Gateway TLS/encrypted cache.
    - ElastiCache in-transit encryption.
    - RDS TLS configuration.
- OU Behavior:
  - `Workloads_Prod`: treated as required.
  - `Workloads_Test`: detect-only, with optional remediation.
  - `Sandbox`: detect-only.

**Phase 3 (Optional PHI/Advanced pack)**

- For PHI-designated OUs/accounts (from `phi_ou_paths`):
  - Stricter TLS and endpoint constraints (e.g., mandatory WAF + HTTPS).
  - Additional SCPs that restrict use of services not approved for PHI.

---

## 8. SSM and Advisory Content

SSM is not enforced solely by CT; we standardize via CT customizations and IaC.

**Implementation**

- StackSet or Terraform module to:
  - Configure SSM Session Manager preferences in each account:
    - KMS-encrypted session logs to CloudWatch log group (e.g., `/aws/ssm/session-logging`).
  - Optionally create VPC endpoints for SSM in relevant VPCs.

**Advisory (deliverable snippet)**

> All production EC2 instances are expected to be managed via AWS Systems Manager.
> This requires:
> - SSM Agent installed in the base image.
> - Network access to SSM endpoints (via public internet or VPC endpoints).
> - IAM roles granting SSM permissions to the instance.

---

## 9. GitHub Actions / CI/CD

### 9.1 Workflows

- `01-validate.yaml`
  - Trigger:
    - PRs.
    - Push to main/trunk.
  - Steps:
    - Terraform/CDK formatting and validation.
    - Lint SCP JSON and CloudFormation templates.
    - Policy-as-code checks (tfsec/checkov/Conftest).

- `02-deploy-landingzone-phase1.yaml`
  - Trigger:
    - Manual (`workflow_dispatch`).
  - Steps:
    - Configure AWS credentials via OIDC (landing zone admin role).
    - Deploy/Update:
      - OUs (if needed).
      - SCPs (IMDSv2, S3 BAP).
      - Config aggregator.
      - Security Hub & GuardDuty delegated admin + auto-enablement.
    - Run post-deploy verification (Section 11).

- `03-deploy-landingzone-phase2.yaml`
  - Deploy Phase 2 (Service Pack A):
    - API Gateway / ElastiCache / RDS guardrails and controls.

- `04-deploy-landingzone-phase3.yaml`
  - Deploy Phase 3 (PHI zoning, advanced TLS/WAF, stricter enforcement).

### 9.2 Error Handling

- IaC errors:
  - Fail workflow, upload logs. No automatic rollback beyond IaC semantics.
- Partial deployments:
  - Re-run plan/synth and attach diff.
- AWS throttling/transient errors:
  - Use provider-level retry and, where necessary, manual backoff wrappers.

---

## 10. Data Handling and Secrets

- No PHI or client secrets in this repo.
- GitHub:
  - Use environments and secrets only for:
    - Role ARNs.
    - Non-sensitive config.
  - No long-lived AWS keys.

- AWS credentials:
  - Always via OIDC + IAM roles.

- KMS key strategy:
  - Logs keys (CloudTrail, Config, Security logs) with tightly limited decrypt.
  - Data keys per environment/domain, with explicit access per application role.

- PHI zoning (Phase 3):
  - PHI-capable OUs/accounts identified by `phi_ou_paths`.
  - Additional SCPs limit:
    - Outbound internet access.
    - Use of unapproved services.
  - Stronger encryption/TLS enforcement for PHI zones.

---

## 11. Testing and Verification Plan

### 11.1 Pre-Deploy

- Validate:
  - Terraform (or CDK) syntax and formatting.
  - SCP JSON format.
  - CloudFormation templates via `validate-template`.
- Policy tests:
  - Conftest/OPA checks for:
    - IMDSv2 SCP logic.
    - S3 BAP SCP logic.
    - Encryption defaults for EBS/RDS in Prod.

### 11.2 Post-Deploy Verification

Provide a verification script in `infra/tests/`, e.g., `verify_landingzone_baseline.py`:

- Verify:
  - OUs exist and accounts are enrolled under the expected OUs.
  - CloudTrail:
    - Org-level multi-region trail exists, targeting Log Archive, KMS-encrypted.
  - Config:
    - Recorders and delivery channels active in each governed account/region.
  - Security Hub & GuardDuty:
    - Security account is delegated admin.
    - Auto-enablement for member accounts is configured.
  - Config aggregator:
    - Aggregates all member accounts.
  - S3:
    - Account-level BAP enabled in all accounts.
  - EBS:
    - Default encryption enabled in each account.
  - IMDSv2 SCP:
    - Test or dry-run `RunInstances` with IMDSv1 and confirm denial.

- Output:
  - JSON or YAML report.
  - CI stores the report as an artifact.

### 11.3 Regression

For any change to:

- SCPs.
- Control Tower customizations (guardrails, proactive controls).
- Security Hub/Config settings.
- OU/phase mappings.

Required:

- Update Conftest/OPA tests.
- Run `01-validate` and relevant deploy workflows against a non-production org
  or dedicated test accounts.
- Record and review before/after plan/synth outputs.

---

## 12. Documentation Deliverables Hooks

Provide reusable snippets under `docs/snippets/`:

- `ou-posture-landingzone.md`
  - Explains `Workloads_Prod`, `Workloads_Test`, `Sandbox` behavior.

- `ssm-imdsv2-advisory-landingzone.md`
  - SSM + IMDSv2 expectations in the context of Control Tower.

- `s3-public-access-advisory-landingzone.md`
  - S3 BAP defaults, exception paths, and versioning guidance.

- `phased-controls-landingzone.md`
  - Table of controls vs Phase (1/2/3) and OU, including:
    - Control name
    - Type (Advisory/Preventive/Detective/Reactive/Proactive)
    - Phase(s) enabled
    - OUs where it applies

Maintain parity between these snippets and the SuperWerker repo so both
implementations stay aligned in behavior and documentation.
