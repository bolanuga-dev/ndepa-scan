package ndepa.iac.section39

import future.keywords.in

default allow = false

# Rule 1: AWS S3 Encryption Requirement
deny[msg] {
    some resource in input.resource.aws_s3_bucket
    not resource.server_side_encryption_configuration
    msg := sprintf("NDPA VIOLATION (Section 39 - Encryption): AWS S3 bucket '%v' lacks server-side encryption configuration.", [resource.name])
}

# Rule 2: AWS RDS Encryption Requirement
deny[msg] {
    some resource in input.resource.aws_db_instance
    resource.storage_encrypted != true
    msg := sprintf("NDPA VIOLATION (Section 39 - Encryption): AWS RDS instance '%v' must have storage_encrypted set to true.", [resource.name])
}

# Rule 3: GCP Storage Bucket Encryption Requirement
deny[msg] {
    some resource in input.resource.google_storage_bucket
    not resource.encryption
    msg := sprintf("NDPA VIOLATION (Section 39 - Encryption): GCP Storage bucket '%v' lacks customer-managed encryption key configuration.", [resource.name])
}
