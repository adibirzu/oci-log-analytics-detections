output "resource_identifiers" {
  description = "Scoped exporter identifiers for operator verification; null when disabled"
  sensitive   = true
  value = local.enabled ? {
    application_id       = oci_functions_application.exporter[0].id
    function_id          = oci_functions_function.exporter[0].id
    topic_id             = oci_ons_notification_topic.evidence[0].id
    operational_topic_id = oci_ons_notification_topic.operational_alerts[0].id
    subscription_id      = try(oci_ons_subscription.function[0].id, null)
    alarm_id             = oci_monitoring_alarm.function_errors[0].id
    log_group_id         = oci_logging_log_group.exporter[0].id
    state_bucket_name    = local.state_bucket_name
    dlq_bucket_name      = local.dlq_bucket_name
  } : null
}

output "function_dynamic_group_matching_rule" {
  description = "Exact resource-principal match for a separately reviewed dynamic group; this module does not create tenancy-level IAM resources"
  value       = local.enabled ? "resource.id = '${oci_functions_function.exporter[0].id}'" : null
  sensitive   = true
}

output "governed_alarm_bindings" {
  description = "Exact governed detection binding keys and Monitoring alarm OCIDs supplied to the exporter"
  sensitive   = true
  value       = local.enabled ? var.splunk_alarm_ids : null
}
