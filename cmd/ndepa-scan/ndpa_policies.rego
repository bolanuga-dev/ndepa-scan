package ndepa.policies

import future.keywords.in

default allow = false

# Allowed regions for PII data storage (NDPA Section 41)
allowed_pii_regions := ["af-south-1", "eu-west-1"]

# Approved third-party egress whitelists for cross-border telemetry (NDPA Section 43)
approved_egress_gateways := ["102.176.0.0/16", "197.210.0.0/16"]

# ==============================================================================
# NDPA SECTION 39: Security of Processing (Encryption at Rest)
# ==============================================================================
deny[msg] {
    some resource in input.resource.aws_s3_bucket
    is_pii_classified(resource)
    not has_server_side_encryption(resource)
    
    msg := sprintf(
        "NDPA VIOLATION (Section 39 - Security Safeguards): S3 Bucket '%v' handles PII but lacks Server-Side Encryption (SSE).",
        [resource.name]
    )
}

# ==============================================================================
# NDPA SECTION 41: Data Localization & Regional Boundaries
# ==============================================================================
deny[msg] {
    some resource in input.resource.aws_s3_bucket
    is_pii_classified(resource)
    not region_is_allowed(resource.region)
    
    msg := sprintf(
        "NDPA VIOLATION (Section 41 - Data Localization): S3 Bucket '%v' contains PII but is deployed in unauthorized region '%v'. Allowed regions: %v",
        [resource.name, resource.region, allowed_pii_regions]
    )
}

# ==============================================================================
# NDPA SECTION 24: Data Minimization & Access Control (Least Privilege)
# ==============================================================================
# 1. Flag Kubernetes / IAM Roles with wildcard permissions on PII resources
deny[msg] {
    some role in input.resource.aws_iam_policy
    is_pii_classified(role)
    has_wildcard_permission(role)
    
    msg := sprintf(
        "NDPA VIOLATION (Section 24 - Access Control & Minimization): IAM Policy '%v' grants wildcard ('*') permissions on resources containing PII.",
        [role.name]
    )
}

# 2. Flag storage resources without defined TTL / Lifecycle policies (Retention Minimization)
deny[msg] {
    some resource in input.resource.aws_s3_bucket
    is_pii_classified(resource)
    not has_lifecycle_retention(resource)
    
    msg := sprintf(
        "NDPA VIOLATION (Section 24 - Storage Limitation): S3 Bucket '%v' holds PII but lacks automated data lifecycle deletion/expiration rules.",
        [resource.name]
    )
}

# ==============================================================================
# NDPA SECTION 43: Cross-Border Data Transfer Safeguards
# ==============================================================================
# Detect unencrypted or unapproved egress endpoints attached to PII workloads
deny[msg] {
    some resource in input.resource.aws_security_group
    is_pii_classified(resource)
    has_unrestricted_egress(resource)
    
    msg := sprintf(
        "NDPA VIOLATION (Section 43 - Cross-Border Transfer Controls): Security Group '%v' attached to PII workload allows unrestricted egress (0.0.0.0/0) without verified transfer controls.",
        [resource.name]
    )
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
is_pii_classified(resource) {
    resource.tags["NDPA-DataClassification"] == "PII"
}

is_pii_classified(resource) {
    resource.tags["NDPA-DataClassification"] == "Sensitive"
}

region_is_allowed(region) {
    region == allowed_pii_regions[_]
}

has_server_side_encryption(resource) {
    resource.encrypted == true
}

has_wildcard_permission(role) {
    role.actions[_] == "*"
}

has_lifecycle_retention(resource) {
    resource.lifecycle_rule_enabled == true
}

has_unrestricted_egress(sg) {
    sg.egress_cidr == "0.0.0.0/0"
}

# ==============================================================================
# KUBERNETES: NDPA SECTION 39 (Encryption in Transit)
# ==============================================================================
# Flag PII-facing Ingress controllers missing TLS configuration
deny[msg] {
    some k8s in input.kubernetes_resources
    k8s.kind == "Ingress"
    is_k8s_pii_classified(k8s)
    not has_k8s_tls(k8s)

    msg := sprintf(
        "NDPA VIOLATION (Section 39 - Transit Encryption): Kubernetes Ingress '%v' routes to PII workloads but lacks TLS termination.",
        [k8s.metadata.name]
    )
}

# ==============================================================================
# KUBERNETES: NDPA SECTION 39 (Compute Security Safeguards)
# ==============================================================================
# Flag PII-processing Pods allowed to run as root
deny[msg] {
    some k8s in input.kubernetes_resources
    k8s.kind == "Pod"
    is_k8s_pii_classified(k8s)
    not is_running_as_non_root(k8s)

    msg := sprintf(
        "NDPA VIOLATION (Section 39 - Compute Security): Kubernetes Pod '%v' handles PII but does not enforce 'runAsNonRoot'.",
        [k8s.metadata.name]
    )
}

# ==============================================================================
# KUBERNETES: NDPA SECTION 24 (Access Control & Least Privilege)
# ==============================================================================
# Flag ClusterRoles with wildcard ('*') verbs or resources affecting PII namespaces
deny[msg] {
    some k8s in input.kubernetes_resources
    k8s.kind == "ClusterRole"
    is_k8s_pii_classified(k8s)
    k8s_has_wildcard(k8s)

    msg := sprintf(
        "NDPA VIOLATION (Section 24 - Access Control): Kubernetes ClusterRole '%v' grants wildcard ('*') administrative privileges over PII environments.",
        [k8s.metadata.name]
    )
}

# ==============================================================================
# KUBERNETES HELPER FUNCTIONS
# ==============================================================================
is_k8s_pii_classified(k8s) {
    k8s.metadata.labels["ndpa-classification"] == "pii"
}

has_k8s_tls(ingress) {
    count(ingress.spec.tls) > 0
}

is_running_as_non_root(pod) {
    pod.spec.securityContext.runAsNonRoot == true
}

k8s_has_wildcard(role) {
    role.rules[_].verbs[_] == "*"
}

k8s_has_wildcard(role) {
    role.rules[_].resources[_] == "*"
}
