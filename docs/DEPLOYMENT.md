# Deployment Guide

## Prerequisites

Before deploying the Dataset Poisoning Detector, ensure you have:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| AWS CLI | 2.x | AWS resource management |
| Terraform | 1.5+ | Infrastructure provisioning |
| kubectl | 1.27+ | Kubernetes cluster management |
| Helm | 3.x | Kubernetes package management |
| Docker | 24+ | Container image building |
| Python | 3.11+ | Local development and testing |

### AWS Account Setup

1. An AWS account with permissions for: EKS, RDS, ElastiCache, S3, KMS, IAM, VPC
2. AWS CLI configured with appropriate credentials (`aws configure`)
3. An S3 bucket for Terraform state (recommended)

---

## AWS Deployment (EKS + RDS + ElastiCache + S3)

### Step 1: Initialize Terraform

```bash
cd terraform/

# Configure backend (optional but recommended for teams)
cat > backend.tf << 'EOF'
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "poison-detector/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
EOF

# Initialize Terraform providers and modules
terraform init
```

### Step 2: Configure Variables

Create a `terraform.tfvars` file:

```hcl
# terraform.tfvars
aws_region          = "us-east-1"
environment         = "production"
cluster_name        = "poison-detector-prod"
vpc_cidr            = "10.0.0.0/16"

# EKS Configuration
eks_node_instance_type = "m5.xlarge"
eks_min_nodes          = 3
eks_max_nodes          = 20
eks_desired_nodes      = 3

# RDS Configuration
rds_instance_class     = "db.r6g.large"
rds_allocated_storage  = 100
rds_multi_az           = true

# ElastiCache (Redis) Configuration
redis_node_type        = "cache.r6g.large"
redis_num_cache_nodes  = 3

# S3 Configuration
s3_audit_bucket_name   = "poison-detector-audit-prod"

# KMS
kms_key_alias          = "alias/poison-detector-prod"
```

### Step 3: Plan and Apply Infrastructure

```bash
# Review the execution plan
terraform plan -out=tfplan

# Apply (creates ~15-20 minutes for EKS cluster)
terraform apply tfplan

# Save outputs for kubectl configuration
terraform output -json > tf-outputs.json
```

### Step 4: Configure kubectl

```bash
# Update kubeconfig with EKS cluster credentials
aws eks update-kubeconfig \
  --name $(terraform output -raw cluster_name) \
  --region $(terraform output -raw aws_region)

# Verify connectivity
kubectl cluster-info
kubectl get nodes
```

### Step 5: Create Namespace and Secrets

```bash
# Create namespace
kubectl create namespace poison-detector

# Create secrets from Terraform outputs
kubectl create secret generic poison-detector-secrets \
  --namespace poison-detector \
  --from-literal=database-url="$(terraform output -raw rds_endpoint)" \
  --from-literal=redis-url="$(terraform output -raw redis_endpoint)" \
  --from-literal=jwt-public-key="$(cat /path/to/jwt-public-key.pem)" \
  --from-literal=master-encryption-key="$(openssl rand -base64 32)"
```

### Step 6: Build and Push Container Image

```bash
# Authenticate to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  $(terraform output -raw ecr_repository_url)

# Build image
docker build -t poison-detector:latest .

# Tag and push
docker tag poison-detector:latest \
  $(terraform output -raw ecr_repository_url):latest
docker push $(terraform output -raw ecr_repository_url):latest
```

### Step 7: Apply Kubernetes Manifests

```bash
# Apply all manifests in order
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/networkpolicy.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/ingress.yaml

# Wait for rollout
kubectl rollout status deployment/poison-detector -n poison-detector --timeout=300s
```

### Step 8: Deploy Observability Stack

```bash
# Apply Prometheus rules
kubectl apply -f observability/prometheus-rules.yaml

# Apply OTel collector config
kubectl apply -f observability/otel-collector.yaml

# Import Grafana dashboard (via Grafana API or ConfigMap)
kubectl create configmap grafana-dashboards \
  --namespace monitoring \
  --from-file=observability/grafana-dashboard.json
```

---

## GCP Deployment (GKE + Cloud SQL + Memorystore + GCS)

### Prerequisites

- GCP project with billing enabled
- `gcloud` CLI configured (`gcloud auth login`)
- APIs enabled: Kubernetes Engine, Cloud SQL, Memorystore, Cloud Storage, Cloud KMS

### Infrastructure Setup

```bash
# Set project
gcloud config set project YOUR_PROJECT_ID

# Create GKE cluster
gcloud container clusters create poison-detector-prod \
  --region us-central1 \
  --num-nodes 3 \
  --machine-type e2-standard-4 \
  --enable-autoscaling \
  --min-nodes 3 \
  --max-nodes 20 \
  --enable-network-policy \
  --workload-pool=YOUR_PROJECT_ID.svc.id.goog

# Create Cloud SQL instance (PostgreSQL)
gcloud sql instances create poison-detector-db \
  --database-version=POSTGRES_15 \
  --tier=db-custom-4-16384 \
  --region=us-central1 \
  --availability-type=REGIONAL \
  --storage-size=100GB \
  --storage-auto-increase

# Create database
gcloud sql databases create poison_detector \
  --instance=poison-detector-db

# Create Memorystore (Redis) instance
gcloud redis instances create poison-detector-cache \
  --size=5 \
  --region=us-central1 \
  --tier=standard \
  --redis-version=redis_7_0

# Create GCS bucket for audit logs
gsutil mb -l us-central1 gs://poison-detector-audit-prod/
gsutil lifecycle set audit-lifecycle.json gs://poison-detector-audit-prod/

# Create Cloud KMS key
gcloud kms keyrings create poison-detector \
  --location us-central1
gcloud kms keys create master-key \
  --location us-central1 \
  --keyring poison-detector \
  --purpose encryption
```

### Deploy Application

```bash
# Get cluster credentials
gcloud container clusters get-credentials poison-detector-prod \
  --region us-central1

# Build and push to Artifact Registry
gcloud builds submit --tag \
  us-central1-docker.pkg.dev/YOUR_PROJECT_ID/poison-detector/api:latest .

# Update k8s manifests with GCP-specific values and apply
kubectl apply -f k8s/
```

---

## Azure Deployment (AKS + Azure Database + Azure Cache + Blob Storage)

### Prerequisites

- Azure subscription with appropriate permissions
- `az` CLI configured (`az login`)
- Resource group created

### Infrastructure Setup

```bash
# Create resource group
az group create --name poison-detector-prod --location eastus

# Create AKS cluster
az aks create \
  --resource-group poison-detector-prod \
  --name poison-detector-cluster \
  --node-count 3 \
  --min-count 3 \
  --max-count 20 \
  --enable-cluster-autoscaler \
  --node-vm-size Standard_D4s_v3 \
  --network-plugin azure \
  --network-policy calico \
  --generate-ssh-keys

# Create Azure Database for PostgreSQL
az postgres flexible-server create \
  --resource-group poison-detector-prod \
  --name poison-detector-db \
  --sku-name Standard_D4s_v3 \
  --storage-size 128 \
  --tier GeneralPurpose \
  --high-availability Enabled \
  --zone 1

# Create Azure Cache for Redis
az redis create \
  --resource-group poison-detector-prod \
  --name poison-detector-cache \
  --sku Premium \
  --vm-size P1 \
  --replicas-per-master 2

# Create Storage Account for audit logs
az storage account create \
  --resource-group poison-detector-prod \
  --name poisondetectoraudit \
  --sku Standard_GRS \
  --kind StorageV2 \
  --access-tier Hot

# Create blob container with immutability policy
az storage container create \
  --account-name poisondetectoraudit \
  --name audit-logs

# Create Key Vault
az keyvault create \
  --resource-group poison-detector-prod \
  --name poison-detector-kv \
  --sku premium
```

### Deploy Application

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group poison-detector-prod \
  --name poison-detector-cluster

# Build and push to ACR
az acr build \
  --registry poisondetectoracr \
  --image poison-detector:latest .

# Apply Kubernetes manifests
kubectl apply -f k8s/
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes (prod) | SQLite | PostgreSQL connection string |
| `REDIS_URL` | Yes (multi-replica) | None | Redis connection string |
| `JWT_PUBLIC_KEY` | Yes | None | PEM-encoded RSA public key for JWT validation |
| `MASTER_ENCRYPTION_KEY` | Yes | None | Base64-encoded AES-256 master key |
| `MTLS_CA_CERT` | No | None | PEM-encoded CA certificate for mTLS |
| `LOG_LEVEL` | No | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `SCORING_WINDOW_SIZE` | No | 10000 | Rolling window size for baseline |
| `CONTAMINATION` | No | 0.05 | Expected poison fraction |
| `ZSCORE_THRESHOLD` | No | 3.0 | Z-score threshold for flagging |
| `VOTE_THRESHOLD` | No | 2 | Minimum votes to flag as poisoned |
| `REFIT_INTERVAL` | No | 1000 | Clean samples between IsolationForest refits |
| `RATE_LIMIT_MAX_REQUESTS` | No | 100 | Requests per window per key |
| `RATE_LIMIT_WINDOW_SECONDS` | No | 60 | Rate limit window duration |
| `AUDIT_LOG_PATH` | No | audit_trail.jsonl | Path to audit log file |
| `AUDIT_RETENTION_YEARS` | No | 7 | Audit log retention period |

### Secrets Management

**AWS**: Use AWS Secrets Manager or Parameter Store with IAM roles for service accounts (IRSA).

```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret \
  --name /poison-detector/prod/jwt-public-key \
  --secret-string "$(cat jwt-public-key.pem)"

# Reference in Kubernetes via External Secrets Operator
```

**GCP**: Use Secret Manager with Workload Identity.

**Azure**: Use Azure Key Vault with Pod Identity.

---

## Verification Steps

After deployment, run through these checks to verify the system is operational:

### 1. Health Check

```bash
# Via kubectl port-forward
kubectl port-forward svc/poison-detector 8080:80 -n poison-detector &

# Check health endpoint
curl -s http://localhost:8080/health | jq .
# Expected: {"status": "healthy", "samples_processed": 0, ...}
```

### 2. Scoring Endpoint

```bash
# Submit a test sample
curl -X POST http://localhost:8080/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"features": [1.0, 2.0, 3.0, 4.0, 5.0]}'
# Expected: {"score": 0.0, "is_poisoned": false, ...}
```

### 3. Metrics Endpoint

```bash
curl -s http://localhost:8080/metrics | head -20
# Expected: Prometheus text format with poison_detector_* metrics
```

### 4. Pod Status

```bash
kubectl get pods -n poison-detector
# Expected: All pods Running, 1/1 Ready

kubectl top pods -n poison-detector
# Expected: Resource usage within limits
```

### 5. HPA Status

```bash
kubectl get hpa -n poison-detector
# Expected: TARGETS showing current CPU/latency, REPLICAS >= minReplicas
```

### 6. Log Verification

```bash
kubectl logs -l app=poison-detector -n poison-detector --tail=50
# Expected: No ERROR level logs, clean startup messages
```

---

## Rollback Procedure

### Application Rollback (Kubernetes)

```bash
# View rollout history
kubectl rollout history deployment/poison-detector -n poison-detector

# Rollback to previous revision
kubectl rollout undo deployment/poison-detector -n poison-detector

# Rollback to specific revision
kubectl rollout undo deployment/poison-detector -n poison-detector --to-revision=3

# Verify rollback
kubectl rollout status deployment/poison-detector -n poison-detector
```

### Infrastructure Rollback (Terraform)

```bash
# View state history (if using S3 backend with versioning)
aws s3api list-object-versions \
  --bucket your-terraform-state-bucket \
  --prefix poison-detector/terraform.tfstate

# Revert to previous state version
terraform plan  # Review what will change
terraform apply
```

### Database Rollback

```bash
# Restore RDS from snapshot (AWS)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier poison-detector-db-restored \
  --db-snapshot-identifier poison-detector-db-daily-2024-01-15

# Update DNS/connection string to point to restored instance
```

### Emergency Procedures

1. **Scale to Zero**: `kubectl scale deployment/poison-detector --replicas=0 -n poison-detector`
2. **Block Traffic**: Remove ingress rule: `kubectl delete ingress poison-detector -n poison-detector`
3. **Circuit Breaker Override**: Set environment variable `CIRCUIT_BREAKER_FORCE_OPEN=true` to force degraded mode
4. **Drain and Cordon**: `kubectl drain <node> --ignore-daemonsets` to remove a problem node from rotation
