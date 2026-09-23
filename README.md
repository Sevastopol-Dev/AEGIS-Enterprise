# Aegis-v4: Event-Driven Self-Healing Cloud Infrastructure

Aegis-v4 is an enterprise-grade automated security remediation framework built on AWS. Designed around the concept of a **digital immune system**, Aegis-v4 mitigates identity compromise, governance friction, and cloud infrastructure drift by detecting and neutralizing threats through honeypots and automated event-driven Lambda workers.

---

## Architecture Overview

Aegis-v4 operates across four phased layers, enforcing Zero Trust network isolation, immutable WORM audit logging, active deception, and serverless auto-remediation.

```text
Aegis-v4 Hardened Cloud Infrastructure
│
├── PHASE 1: HARDENED NETWORK ARCHITECTURE (3-Tier Isolated VPC: 10.0.0.0/16)
│   ├── Public Subnet (10.0.1.0/24) [us-east-1a]
│   │   ├── Internet Gateway (aegis-igw)
│   │   └── ALB Security Group (aegis-alb-sg) -> Port 443 Ingress
│   │
│   ├── Private App Subnet (10.0.10.0/24) [us-east-1a]
│   │   ├── App Security Group (aegis-app-sg) -> Inbound 8080 from ALB SG
│   │   └── S3 VPC Gateway Endpoint (aegis-s3-gateway-endpoint)
│   │
│   └── Air-Gapped DB Subnet (10.0.20.0/24) [us-east-1a]
│       └── Isolated DB Security Group (aegis-db-sg) -> Inbound 5432 strictly from App SG
│
├── PHASE 2: IMMUTABLE AUDIT & TELEMETRY ENGINE (Compliance & Storage)
│   ├── KMS Customer Managed Key (aegis-audit-kms) -> 30-Day Deletion / Auto-Rotation
│   └── S3 WORM Audit Bucket (aegis-v4-immutable-audit-ledger-${region})
│       ├── Object Lock: COMPLIANCE Mode (90-Day Retention)
│       └── Server-Side Encryption: AWS KMS
│
├── PHASE 3: SERVERLESS DECEPTION LABYRINTH (Active Lure Layer)
│   ├── Decoy IAM User (bank-core-ledger-svc-admin)
│   ├── Honeytoken Access Key (aws_iam_access_key.honeytoken_key)
│   └── Decoy S3 Bucket (pnc-customer-ssn-ledger-backup-prod)
│
└── PHASE 4: EVENT-DRIVEN IMMUNE ENGINE (Automated Neutralization)
    ├── DynamoDB Table (aegis-v4-circuit-breaker-state) -> Rate-limiting circuit breaker
    ├── EventBridge Rule (aegis-honeytoken-triggered) -> Monitors honeytoken access key ID
    └── Immune Lambda Worker (aegis-v4-immune-worker)
        ├── Runtime: Python 3.11
        └── Permissions: iam:PutUserPolicy, iam:PutRolePolicy, iam:AttachUserPolicy

```

---

## Technical Specifications

### Phase 1: Hardened Network Architecture

* **CIDR & Subnet Tiering:** Provisions a main VPC (`10.0.0.0/16`) divided into public (`10.0.1.0/24`), private app (`10.0.10.0/24`), and isolated database (`10.0.20.0/24`) subnets.


* **Zero Internet Route for DB:** The isolated DB subnet intentionally lacks route table associations to prevent outbound internet egress.


* **S3 Gateway Endpoint:** Integrates a free S3 VPC Gateway Endpoint attached to public and private route tables to route S3 API traffic internally without NAT fees.


* **Dependency-Cycle-Free Security Groups:** Enforces strict security group chaining across ALB (`443`), App (`8080`), and DB (`5432`) tiers, using standalone egress rules to prevent dependency cycles.



### Phase 2: Immutable Audit & Telemetry Engine

* **KMS Key Management:** Creates a customer-managed key (`aegis-audit-kms`) with 30-day deletion windows and automatic yearly key rotation.


* **WORM Compliance Retention:** Configures S3 Object Lock in strict `COMPLIANCE` mode with a 90-day retention rule, enforcing versioning and blocking bucket deletion or object overwrites.


* **Public Access Block:** Completely disables public ACLs, public policies, and public bucket exposure.



### Phase 3: Serverless Deception Labyrinth

* **Honeytoken Identity:** Plants a decoy IAM user (`bank-core-ledger-svc-admin`) with no attached policies. Any attempt to use its access key triggers an immediate security tripwire.


* **Decoy Target:** Provisions an unadvertised decoy S3 bucket (`pnc-customer-ssn-ledger-backup-prod`) with `tfsec` static analysis suppressions to act as a honeypot target.



### Phase 4: Event-Driven Immune Engine

* **EventBridge Tripwire:** Configures an EventBridge rule (`aegis-honeytoken-triggered`) matching API activity originating from the honeytoken `accessKeyId`.


* **Circuit Breaker Ledger:** Uses a DynamoDB table (`aegis-v4-circuit-breaker-state`) with `PAY_PER_REQUEST` billing and TTL enabled for rate-limiting auto-remediations.


* **Immune Lambda Worker:** Executes a Python 3.11 Lambda function (`aegis-v4-immune-worker`) with IAM permissions to dynamically attach inline `Deny *` policies and revoke active STS sessions.



---

## Deployment & Verification

### 1. Initialize & Apply Infrastructure

```bash
# Initialize HashiCorp AWS Provider
terraform init

# Validate configuration syntax
terraform validate

# Provision the stack
terraform apply -auto-approve

```

### 2. Verify Output Values

Upon successful deployment, Terraform outputs the generated honeytoken credentials for monitoring:

```bash
Outputs:

honeytoken_access_key_id = "AKIA..."
honeytoken_user_name     = "bank-core-ledger-svc-admin"

```

---

## License

This project is licensed under the [MIT License](https://www.google.com/search?q=LICENSE&utm_source=gemini).
