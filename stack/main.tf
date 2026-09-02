# Validate the target compartment exists
data "oci_identity_compartment" "target" {
  id = var.compartment_id
}

# Discover the Log Analytics namespace for this tenancy
data "oci_log_analytics_namespaces" "this" {
  compartment_id = var.tenancy_ocid
}

locals {
  la_namespace = data.oci_log_analytics_namespaces.this.namespace_collection[0].items[0].namespace

  stream_definitions = {
    "soc-detection-oci-audit"      = { log_source = "OCI Audit Logs" }
    "soc-detection-cloud-guard"    = { log_source = "OCI Cloud Guard Problems" }
    "soc-detection-linux-audit"    = { log_source = "SOC Linux Syslog Logs" }
    "soc-detection-windows-sysmon" = { log_source = "Windows Sysmon Operational Logs" }
  }
}

module "splunk_evidence_exporter" {
  source = "./modules/splunk_evidence_exporter"

  enable_splunk_evidence_exporter     = var.enable_splunk_evidence_exporter
  enable_alarm_actions                = var.enable_splunk_evidence_exporter_alarm_actions
  enable_notification_subscription    = var.enable_splunk_evidence_exporter_subscription
  compartment_id                      = var.compartment_id
  log_analytics_compartment_id        = var.compartment_id
  object_storage_namespace            = var.splunk_evidence_exporter_object_storage_namespace
  existing_state_bucket_name          = var.splunk_evidence_exporter_existing_state_bucket_name
  existing_dlq_bucket_name            = var.splunk_evidence_exporter_existing_dlq_bucket_name
  function_subnet_ids                 = var.splunk_evidence_exporter_function_subnet_ids
  function_network_security_group_ids = var.splunk_evidence_exporter_function_nsg_ids
  function_image                      = var.splunk_evidence_exporter_function_image
  function_image_digest               = var.splunk_evidence_exporter_function_image_digest
  splunk_hec_secret_id                = var.splunk_evidence_exporter_hec_secret_id
  splunk_hec_url                      = var.splunk_evidence_exporter_hec_url
  splunk_hec_index                    = var.splunk_evidence_exporter_hec_index
}
