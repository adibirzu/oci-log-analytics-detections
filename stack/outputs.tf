output "la_namespace" {
  description = "Log Analytics namespace"
  value       = local.la_namespace
}

output "log_group_id" {
  description = "OCID of the effective Log Analytics log group"
  value       = local.effective_log_group_id
}

output "deployment_mode" {
  description = "Active deployment strategy (greenfield or attach_existing)"
  value       = var.deployment_mode
}

output "compartment_id" {
  description = "Target compartment OCID"
  value       = var.compartment_id
}

output "stream_ids" {
  description = "Map of stream name to OCID"
  value       = { for k, v in oci_streaming_stream.soc_detection : k => v.id }
}

output "service_connector_ids" {
  description = "Map of service connector name to OCID"
  value       = { for k, v in oci_sch_service_connector.soc_detection : k => v.id }
}

output "splunk_evidence_exporter_resource_identifiers" {
  description = "Scoped exporter identifiers for operator verification; null when disabled"
  value       = module.splunk_evidence_exporter.resource_identifiers
  sensitive   = true
}

output "splunk_evidence_exporter_dynamic_group_matching_rule" {
  description = "Exact resource-principal match for separate IAM review; null when disabled"
  value       = module.splunk_evidence_exporter.function_dynamic_group_matching_rule
  sensitive   = true
}

output "splunk_evidence_exporter_governed_alarm_bindings" {
  description = "Exact governed detection binding keys and Monitoring alarm OCIDs supplied to the exporter"
  sensitive   = true
  value       = module.splunk_evidence_exporter.governed_alarm_bindings
}
