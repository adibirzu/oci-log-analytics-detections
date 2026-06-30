# OCI Resource Manager Deployment Package

The `stack/` directory contains the Terraform definition used to deploy the supported OCI Log Analytics detection content. It is packaged by `scripts/build_orm_stack.py` and exposed by Forge's **Deploy to OCI** workspace for dynamic deployments.

## Scope

The package includes the committed Terraform stack, deployment scripts, generated queries, mappings, and schemas needed by the supported automation. It intentionally excludes local credentials, Terraform state, ignored caches, and disposable `test_data/`. The package does not export or move raw customer logs.

The stack can create or update OCI Log Analytics content and its declared supporting resources, including log groups, streams, Service Connector Hub resources, custom log sources, dashboards, and saved searches. Review the Terraform plan for the selected variables before applying it.

## Customer Deployment

1. In Forge, open **Deploy to OCI** and acknowledge the privileged deployment boundary.
2. Download `oci-log-analytics-deployment.zip`.
3. Sign in to OCI and open **Resource Manager → Stacks**.
4. Create a stack from the zip, select the intended compartment and region, and set the deployment options.
5. Run **Plan** and verify every proposed change.
6. Run **Apply** only after the plan and IAM permissions match the intended scope.

Forge never accepts OCI credentials or target-compartment identifiers. Resource Manager authenticates the customer and records the plan/apply in the customer's tenancy.

## Build Locally

```bash
python3 scripts/build_orm_stack.py --out /tmp/oci-log-analytics-deployment.zip
unzip -t /tmp/oci-log-analytics-deployment.zip
```

`stack/build_stack.sh` is a convenience wrapper around the same generator.
