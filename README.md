# OCI Log Analytics Detection Rules

This project provides a comprehensive collection of detection rules for Oracle Cloud Infrastructure (OCI) Log Analytics. It leverages the [Sigma](https://github.com/SigmaHQ/sigma) rule format as a standardized source and includes tooling to convert these rules into OCI Log Analytics Query Language (OCL).

## Current Status
- **Total Rules:** 100+
- **Categories:** OCI Audit, Cloud Guard, Linux Suspicious Binaries, Windows LOLBins.
- **Format:** Sigma (YAML) -> OCL (JSON).

## Project Structure

- `rules/`: Source detection rules in Sigma YAML format.
    - `cloud/oci/`: OCI Audit and Cloud Guard rules.
    - `linux/`: Linux OS level rules.
    - `windows/`: Windows OS level rules.
- `queries/`: Generated OCI Log Analytics queries ready for import/usage.
- `scripts/`: Tools for rule conversion and management.
- `config/`: Configuration files, including field mappings.

## Usage

### Generating Queries
To regenerate the OCL queries from the Sigma rules (e.g., after editing a rule or mapping):

```bash
python3 scripts/convert_sigma.py
```

The output JSON files in `queries/` contain the `query` string which can be used in OCI Log Analytics.

### Example Query Output
**OCI Console Login from Unusual IP**
```sql
'Log Source' = 'OCI Audit Logs' | where Event Type = 'com.oraclecloud.identity.authentication.login' and Status = 'Success'
```

## Adding New Rules
1. Create a new YAML file in the appropriate `rules/` subdirectory.
2. Follow the Sigma specification.
3. Run `python3 scripts/convert_sigma.py`.