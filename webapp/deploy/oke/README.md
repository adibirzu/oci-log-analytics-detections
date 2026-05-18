# Forge Webapp on endemo OKE

This deploys the integrated `webapp/` Forge frontend into the existing Octo APM OKE environment. The live pattern is OCI Load Balancer host routing to a Kubernetes NodePort service; do not create a second public load balancer for this UI.

Required production posture:

- Browser traffic enters through `https://convert.octodemo.cloud`.
- The OCI Load Balancer terminates TLS with the same certificate used by the APM demo hosts.
- The service is exposed inside OKE as NodePort `30082`.
- `/api/forge/convert` stays behind the frontend origin and proxies to `LOGAN_FORGE_BACKEND_URL`, which should be an OCI API Gateway endpoint protected by WAF.
- If the backend secret is absent, the frontend uses the bundled read-only artifacts and `scripts/logan_workbench_convert.py`.
- Backend credentials live in the optional `logan-forge-backend` Kubernetes secret. Do not put API tokens or tenancy-specific values in manifests.

## Build and Deploy

Run from `webapp/`:

```bash
export FORGE_IMAGE="<ocir-region>.ocir.io/<namespace>/logan-forge:<tag>"
export FORGE_IMAGE_TAG="<tag>"
export FORGE_NODEPORT="30082"

./deploy/oke/stage-detections-runtime.sh
docker build -t "$FORGE_IMAGE" .
docker push "$FORGE_IMAGE"
kubectl create namespace logan-forge --dry-run=client -o yaml | kubectl apply -f -
kubectl get secret ocir-pull-secret -n octo-drone-shop -o yaml \
  | sed 's/namespace: octo-drone-shop/namespace: logan-forge/' \
  | kubectl apply -f -
envsubst < deploy/oke/forge-frontend.yaml | kubectl apply -f -
kubectl rollout status deployment/logan-forge -n logan-forge
kubectl get svc logan-forge-lb -n logan-forge
```

## Wire the Existing Load Balancer

```bash
OCI_PROFILE=emdemo \
FORGE_HOSTNAME=convert.octodemo.cloud \
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
OCI_PROFILE=cap \
OCI_DNS_ZONE_NAME=octodemo.cloud \
FORGE_RECORD_NAME=convert.octodemo.cloud \
FORGE_LB_OCID=<existing-octo-apm-lb-ocid> \
FORGE_LB_PROFILE=emdemo \
./deploy/oke/update-forge-dns.sh
```
