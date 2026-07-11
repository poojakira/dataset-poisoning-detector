# =============================================================================
# Dataset Poisoning Detector - Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------

output "eks_cluster_endpoint" {
  description = "Endpoint for the EKS cluster API server"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_certificate_authority" {
  description = "Base64 encoded certificate data for the EKS cluster"
  value       = module.eks.cluster_certificate_authority
  sensitive   = true
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

# -----------------------------------------------------------------------------
# RDS
# -----------------------------------------------------------------------------

output "rds_endpoint" {
  description = "Aurora PostgreSQL cluster endpoint (writer)"
  value       = module.rds.cluster_endpoint
}

output "rds_port" {
  description = "Aurora PostgreSQL cluster port"
  value       = module.rds.cluster_port
}

# -----------------------------------------------------------------------------
# Redis
# -----------------------------------------------------------------------------

output "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint address"
  value       = module.redis.primary_endpoint
}

output "redis_reader_endpoint" {
  description = "ElastiCache Redis reader endpoint address"
  value       = module.redis.reader_endpoint
}

# -----------------------------------------------------------------------------
# S3
# -----------------------------------------------------------------------------

output "s3_bucket_name" {
  description = "Name of the S3 bucket for sample archival"
  value       = module.s3.bucket_name
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for sample archival"
  value       = module.s3.bucket_arn
}

# -----------------------------------------------------------------------------
# KMS
# -----------------------------------------------------------------------------

output "kms_key_arn" {
  description = "ARN of the KMS CMK for envelope encryption"
  value       = aws_kms_key.main.arn
}

output "kms_key_id" {
  description = "ID of the KMS CMK for envelope encryption"
  value       = aws_kms_key.main.key_id
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}
