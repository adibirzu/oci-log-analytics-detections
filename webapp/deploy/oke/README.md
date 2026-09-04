# Forge Webapp on OCI OKE

This deploys the integrated `webapp/` Forge frontend into an existing OCI OKE environment. The supported pattern is OCI Load Balancer host routing to a Kubernetes NodePort service; do not create a second public load balancer for this UI.

Required production posture:

- Browser traffic enters through the operator-supplied `FORGE_HOSTNAME`.
- The OCI Load Balancer terminates TLS with a certificate valid for that hostname.
- The service is exposed inside OKE through the reviewed `FORGE_NODEPORT`.
- `/api/forge/convert` stays behind the frontend origin and proxies to `LOGAN_FORGE_BACKEND_URL`, which should be an OCI API Gateway endpoint protected by WAF.
- If the backend secret is absent, the frontend uses the bundled read-only artifacts and `scripts/logan_workbench_convert.py`.
- Backend credentials live in the optional `logan-forge-backend` Kubernetes secret. Do not put API tokens or tenancy-specific values in manifests.

## Build and Deploy

Run from `webapp/`:

```bash
export FORGE_IMAGE="<ocir-region>.ocir.io/<namespace>/logan-forge:<tag>"
export FORGE_IMAGE_TAG="<tag>"
export FORGE_NODEPORT="30082"
export FORGE_HOSTNAME="<FORGE_HOSTNAME>"
export FORGE_ALLOWED_ORIGINS="https://${FORGE_HOSTNAME},http://logan-forge-lb.logan-forge.svc,http://logan-forge-lb.logan-forge.svc.cluster.local"
export SOURCE_IMAGE_PULL_SECRET_NAMESPACE="<SOURCE_NAMESPACE>"

./deploy/oke/stage-detections-runtime.sh
kubectl get nodes -o custom-columns=NAME:.metadata.name,ARCH:.status.nodeInfo.architecture
export FORGE_PLATFORM="linux/amd64" # set from the reviewed node architecture
docker buildx build --platform "$FORGE_PLATFORM" -t "$FORGE_IMAGE" --push .
kubectl create namespace logan-forge --dry-run=client -o yaml | kubectl apply -f -
kubectl get secret ocir-pull-secret -n "$SOURCE_IMAGE_PULL_SECRET_NAMESPACE" -o yaml \
  | sed "s/namespace: $SOURCE_IMAGE_PULL_SECRET_NAMESPACE/namespace: logan-forge/" \
  | kubectl apply -f -
envsubst < deploy/oke/forge-frontend.yaml | kubectl apply -f -
kubectl rollout status deployment/logan-forge -n logan-forge
kubectl get svc logan-forge-lb -n logan-forge
```

Use the `--platform` value that matches the architecture reported by
`kubectl get nodes`; do not assume AMD64. An image built for a different
architecture can pull successfully but fail when scheduled.

## Wire the Existing Load Balancer

```bash
OCI_PROFILE=<OCI_PROFILE> \
OUTPUTS_FILE=<REVIEWED_LB_OUTPUTS_JSON> \
OKE_CLUSTER_NAME=<KUBECTL_CONTEXT> \
FORGE_HOSTNAME_NAME=convert \
FORGE_HOSTNAME=<FORGE_HOSTNAME> \
FORGE_NODEPORT=30082 \
./deploy/oke/wire-existing-lb-convert.sh --apply

OCI_PROFILE=<OCI_PROFILE> \
OUTPUTS_FILE=<REVIEWED_LB_OUTPUTS_JSON> \
OKE_CLUSTER_NAME=<KUBECTL_CONTEXT> \
FORGE_HOSTNAME_NAME=forge \
FORGE_HOSTNAME=<ALTERNATE_FORGE_HOSTNAME> \
FORGE_NODEPORT=30082 \
./deploy/oke/wire-existing-lb-convert.sh --apply
```

Create the backend secret only from a secret store or CI secret variables:

```bash
kubectl create secret generic logan-forge-backend \
  -n logan-forge \
  --from-literal=backend-url="$LOGAN_FORGE_BACKEND_URL" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Add the `backend-token` key through your approved secret manager or CI secret injection flow before enabling the write-capable backend.

## Update DNS

After the OCI LB backend set and host routing are wired to the NodePort, update DNS from the configured OCI profile:

```bash
OCI_PROFILE=<OCI_STAGING_PROFILE> \
OCI_DNS_ZONE_NAME=<DNS_ZONE_NAME> \
FORGE_RECORD_NAME=<FORGE_HOSTNAME> \
FORGE_LB_OCID=<EXISTING_OCI_LB_OCID> \
FORGE_LB_PROFILE=<OCI_LB_PROFILE> \
./deploy/oke/update-forge-dns.sh
```

Repeat with a separately reviewed `FORGE_RECORD_NAME` when publishing an alternate Forge hostname.
