# Splunk evidence exporter dependency lock

This is the reproducible, reviewable dependency input for the Function build.
The pins are intentionally duplicated from `function/requirements.txt` so a
builder can compare the source and lock before resolving artifacts:

```text
fdk==0.1.90
oci==2.160.3
```

This repository does not have verified package artifact hashes offline. The
file is therefore not a pip installation input and must not be treated as a
production lock by itself. Before accepting a production image, an authorized
external builder must resolve these exact pins into a hash-locked file and
run:

```bash
python -m pip install --require-hashes -r requirements-hashed.lock
```

The acceptance gate must fail closed unless that hash-locked resolution is
verified and retained with SBOM, SCA, SAST, IaC, container-scan, signature,
and immutable image-digest evidence. Mutable `func.yaml` build/run images are
local-only metadata.
