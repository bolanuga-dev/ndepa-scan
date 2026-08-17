package ndepa.policies

deny[msg] {
    input.kind == "Deployment"
    not input.metadata.labels.env
    msg := sprintf("CUSTOM RULE VIOLATION: Deployment '%s' must have an 'env' label.", [input.metadata.name])
}
