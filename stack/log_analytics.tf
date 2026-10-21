resource "oci_log_analytics_log_analytics_log_group" "soc_detection" {
  count          = (var.deployment_mode == "attach_existing" && var.existing_log_group_id != "") || var.use_existing_log_group ? 0 : 1
  compartment_id = var.compartment_id
  namespace      = local.la_namespace
  display_name   = var.log_group_name
  description    = var.log_group_description
}
