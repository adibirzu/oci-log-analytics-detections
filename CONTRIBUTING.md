# Contributing to OCI Log Analytics Detection Rules

We welcome contributions to expand the coverage of detection rules!

## How to Contribute

1.  **Fork the repository** (if applicable) or create a new branch.
2.  **Add a Rule:**
    - Create a new YAML file in `rules/`.
    - Follow the [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification).
    - Ensure you use standard field names where possible, or update `config/sigma_oci_mapping.yaml` if you introduce new specific fields.
3.  **Validate:**
    - Run `python3 scripts/convert_sigma.py` to ensure your rule compiles to a valid OCL query.
    - Check the output in `queries/` to verify the logic.
4.  **Submit a Pull Request.**

## Style Guide
- **Titles:** Title Case, descriptive (e.g., "Suspicious Sudo Usage", not "sudo rule").
- **IDs:** Generate a unique UUID for new rules.
- **Tags:** Use MITRE ATT&CK tags (e.g., `attack.initial_access`) or OCI specific tags (`oci.audit`).

## Field Mapping
If your rule uses a field not yet mapped to OCI Log Analytics:
1. Open `config/sigma_oci_mapping.yaml`.
2. Add the mapping under `field_mappings`.
   ```yaml
   sigma_field_name: "OCI Log Analytics Field Name"
   ```
