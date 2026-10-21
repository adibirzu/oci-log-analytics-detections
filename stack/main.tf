# Validate the target compartment exists
data "oci_identity_compartment" "target" {
  id = var.compartment_id
}

# Discover the Log Analytics namespace for this tenancy
data "oci_log_analytics_namespaces" "this" {
  compartment_id = var.tenancy_ocid
}

locals {
  la_namespace           = var.existing_log_analytics_namespace != "" ? var.existing_log_analytics_namespace : data.oci_log_analytics_namespaces.this.namespace_collection[0].items[0].namespace
  effective_log_group_id = (var.deployment_mode == "attach_existing" && var.existing_log_group_id != "") || var.use_existing_log_group ? var.existing_log_group_id : (length(oci_log_analytics_log_analytics_log_group.soc_detection) > 0 ? oci_log_analytics_log_analytics_log_group.soc_detection[0].id : var.existing_log_group_id)

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
  log_analytics_namespace             = local.la_namespace
  alarm_binding_mode                  = var.splunk_evidence_exporter_alarm_binding_mode
  splunk_alarm_ids                    = var.splunk_evidence_exporter_alarm_ids
  object_storage_namespace            = var.splunk_evidence_exporter_object_storage_namespace
  existing_state_bucket_name          = var.splunk_evidence_exporter_existing_state_bucket_name
  existing_dlq_bucket_name            = var.splunk_evidence_exporter_existing_dlq_bucket_name
  function_subnet_ids                 = var.splunk_evidence_exporter_function_subnet_ids
  function_network_security_group_ids = var.splunk_evidence_exporter_function_nsg_ids
  function_image                      = var.splunk_evidence_exporter_function_image
  function_image_digest               = var.splunk_evidence_exporter_function_image_digest
  function_attestation_sha256         = var.splunk_evidence_exporter_function_attestation_sha256
  function_provenance_sha256          = var.splunk_evidence_exporter_function_provenance_sha256
  function_attestation_path           = var.splunk_evidence_exporter_function_attestation_path
  function_provenance_path            = var.splunk_evidence_exporter_function_provenance_path
  splunk_hec_secret_id                = var.splunk_evidence_exporter_hec_secret_id
  splunk_hec_url                      = var.splunk_evidence_exporter_hec_url
  splunk_hec_index                    = var.splunk_evidence_exporter_hec_index
  evidence_delivery_target            = var.splunk_evidence_exporter_delivery_target
  evidence_stream_id                  = var.splunk_evidence_exporter_stream_id
  evidence_stream_messages_endpoint   = var.splunk_evidence_exporter_stream_messages_endpoint
}
