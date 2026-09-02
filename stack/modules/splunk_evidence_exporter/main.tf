terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

locals {
  enabled             = var.enable_splunk_evidence_exporter
  create_state_bucket = local.enabled && var.existing_state_bucket_name == ""
  create_dlq_bucket   = local.enabled && var.existing_dlq_bucket_name == ""
  state_bucket_name   = var.existing_state_bucket_name != "" ? var.existing_state_bucket_name : try(oci_objectstorage_bucket.state[0].name, "")
  dlq_bucket_name     = var.existing_dlq_bucket_name != "" ? var.existing_dlq_bucket_name : try(oci_objectstorage_bucket.dlq[0].name, "")

  function_config = {
    OBJECT_STORAGE_NAMESPACE                 = var.object_storage_namespace
    SPLUNK_EVIDENCE_STATE_BUCKET             = local.state_bucket_name
    SPLUNK_EVIDENCE_DLQ_BUCKET               = local.dlq_bucket_name
    OCI_LOG_ANALYTICS_COMPARTMENT_ID         = var.log_analytics_compartment_id
    OCI_LOG_ANALYTICS_NAMESPACE              = var.log_analytics_namespace
    SPLUNK_ALARM_BINDINGS                    = jsonencode({ for binding_key, alarm_id in var.splunk_alarm_ids : alarm_id => binding_key })
    OCI_LOG_ANALYTICS_COMPARTMENT_IN_SUBTREE = tostring(var.log_analytics_compartment_in_subtree)
    SPLUNK_HEC_SECRET_ID                     = var.splunk_hec_secret_id
    SPLUNK_HEC_URL                           = var.splunk_hec_url
    SPLUNK_HEC_INDEX                         = var.splunk_hec_index
    SPLUNK_HEC_SOURCETYPE                    = var.splunk_hec_sourcetype
    SPLUNK_HEC_ACKNOWLEDGEMENT_MODE          = var.splunk_hec_acknowledgement_mode
    SPLUNK_HEC_TIMEOUT_SECONDS               = tostring(var.splunk_hec_timeout_seconds)
    SPLUNK_EVIDENCE_MAX_ROWS                 = tostring(var.splunk_evidence_max_rows)
    SPLUNK_HEC_MAX_BATCH_EVENTS              = tostring(var.splunk_hec_max_batch_events)
    SPLUNK_EVIDENCE_MAX_ATTEMPTS             = tostring(var.splunk_evidence_max_attempts)
    SPLUNK_EVIDENCE_LOOKBACK_SECONDS         = tostring(var.splunk_evidence_lookback_seconds)
    SPLUNK_EVIDENCE_OVERLAP_SECONDS          = tostring(var.splunk_evidence_overlap_seconds)
    SPLUNK_EVIDENCE_MAX_WINDOW_SECONDS       = tostring(var.splunk_evidence_max_window_seconds)
    SPLUNK_EXPORTER_TELEMETRY_NAMESPACE      = var.exporter_telemetry_namespace
  }

  # These are governed contracts, not discovered tenant alarms.  The operator
  # reviews the metric query and explicitly enables actions separately.
  governed_detection_alarm_ids = toset([
    "object-storage-new-external-source", "oci-audit-failures", "oci-iam-policy-change",
    "vcn-rejected-traffic-spike", "windows-access-administrator-logon",
    "windows-access-failed-logon-burst", "windows-access-new-local-user",
    "windows-access-privileged-group-add", "windows-access-rdp-after-hours",
  ])
}

resource "oci_objectstorage_bucket" "state" {
  count = local.create_state_bucket ? 1 : 0

  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "${var.resource_name_prefix}-state"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  freeform_tags  = var.freeform_tags
}

resource "oci_objectstorage_bucket" "dlq" {
  count = local.create_dlq_bucket ? 1 : 0

  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "${var.resource_name_prefix}-dlq"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  freeform_tags  = var.freeform_tags
}

resource "oci_objectstorage_object_lifecycle_policy" "state" {
  count = local.create_state_bucket ? 1 : 0

  bucket    = oci_objectstorage_bucket.state[0].name
  namespace = var.object_storage_namespace

  rules {
    action      = "DELETE"
    is_enabled  = true
    name        = "delete-superseded-checkpoints"
    target      = "previous-object-versions"
    time_amount = var.state_previous_version_retention_days
    time_unit   = "DAYS"
  }
}

resource "oci_objectstorage_object_lifecycle_policy" "dlq" {
  count = local.create_dlq_bucket ? 1 : 0

  bucket    = oci_objectstorage_bucket.dlq[0].name
  namespace = var.object_storage_namespace

  rules {
    action      = "DELETE"
    is_enabled  = true
    name        = "delete-expired-dlq-records"
    target      = "objects"
    time_amount = var.dlq_retention_days
    time_unit   = "DAYS"
  }

  rules {
    action      = "DELETE"
    is_enabled  = true
    name        = "delete-superseded-dlq-records"
    target      = "previous-object-versions"
    time_amount = var.dlq_previous_version_retention_days
    time_unit   = "DAYS"
  }
}

resource "oci_functions_application" "exporter" {
  count = local.enabled ? 1 : 0

  compartment_id             = var.compartment_id
  display_name               = "${var.resource_name_prefix}-app"
  subnet_ids                 = var.function_subnet_ids
  network_security_group_ids = var.function_network_security_group_ids
  freeform_tags              = var.freeform_tags

  logging {
    line_format = "JSON"
  }

  lifecycle {
    precondition {
      condition     = length(var.function_subnet_ids) > 0
      error_message = "Existing Function subnet OCIDs are required; this module does not create a VCN."
    }
  }
}

resource "oci_functions_function" "exporter" {
  count = local.enabled ? 1 : 0

  application_id     = oci_functions_application.exporter[0].id
  display_name       = "${var.resource_name_prefix}-function"
  image              = "${var.function_image}@${var.function_image_digest}"
  image_digest       = var.function_image_digest
  memory_in_mbs      = var.function_memory_in_mbs
  timeout_in_seconds = var.function_timeout_in_seconds
  config             = local.function_config
  freeform_tags      = var.freeform_tags

  lifecycle {
    precondition {
      condition     = var.function_image != ""
      error_message = "A reviewed OCI Registry image reference is required when the exporter is enabled."
    }

    precondition {
      condition     = can(regex("^sha256:[0-9a-f]{64}$", var.function_image_digest))
      error_message = "A non-empty sha256 image digest is required when the exporter is enabled."
    }

    precondition {
      condition     = var.splunk_hec_secret_id != ""
      error_message = "An existing OCI Vault secret OCID is required; never pass the HEC token value."
    }

    precondition {
      condition     = var.splunk_hec_url != "" && var.splunk_hec_index != ""
      error_message = "The reviewed HTTPS HEC endpoint and target index are required."
    }

    precondition {
      condition = (
        set(keys(var.splunk_alarm_ids)) == local.governed_detection_alarm_ids
        && alltrue([
          for alarm_id in values(var.splunk_alarm_ids) : can(regex("^ocid1\\.alarm\\.", alarm_id))
        ])
      )
      error_message = "When the exporter is enabled, splunk_alarm_ids must contain exactly the governed detection keys and an OCID for every Monitoring alarm."
    }
  }

  depends_on = [
    oci_objectstorage_object_lifecycle_policy.state,
    oci_objectstorage_object_lifecycle_policy.dlq,
  ]
}

resource "oci_ons_notification_topic" "evidence" {
  count = local.enabled ? 1 : 0

  compartment_id = var.compartment_id
  name           = "${var.resource_name_prefix}-topic"
  description    = "Reviewed alarm trigger topic for the Splunk evidence exporter"
  freeform_tags  = var.freeform_tags
}

resource "oci_ons_notification_topic" "operational_alerts" {
  count = local.enabled ? 1 : 0

  compartment_id = var.compartment_id
  name           = "${var.resource_name_prefix}-operational-alerts"
  description    = "Exporter health alarm topic; intentionally separate from the Function trigger topic"
  freeform_tags  = var.freeform_tags
}

resource "oci_ons_subscription" "function" {
  count = local.enabled && var.enable_notification_subscription ? 1 : 0

  compartment_id = var.compartment_id
  protocol       = "ORACLE_FUNCTIONS"
  topic_id       = oci_ons_notification_topic.evidence[0].id
  endpoint       = oci_functions_function.exporter[0].id
  freeform_tags  = var.freeform_tags

  lifecycle {
    precondition {
      condition = (
        set(keys(var.splunk_alarm_ids)) == local.governed_detection_alarm_ids
        && alltrue([
          for alarm_id in values(var.splunk_alarm_ids) : can(regex("^ocid1\\.alarm\\.", alarm_id))
        ])
      )
      error_message = "The Notifications subscription requires complete governed splunk_alarm_ids bindings."
    }
  }
}

resource "oci_logging_log_group" "exporter" {
  count = local.enabled ? 1 : 0

  compartment_id = var.compartment_id
  display_name   = "${var.resource_name_prefix}-logs"
  description    = "Service logs for Splunk evidence exporter Function invocations"
  freeform_tags  = var.freeform_tags
}

resource "oci_logging_log" "function_invocation" {
  count = local.enabled ? 1 : 0

  display_name       = "${var.resource_name_prefix}-invoke"
  log_group_id       = oci_logging_log_group.exporter[0].id
  log_type           = "SERVICE"
  is_enabled         = true
  retention_duration = var.function_log_retention_days
  freeform_tags      = var.freeform_tags

  configuration {
    compartment_id = var.compartment_id

    source {
      category    = "invoke"
      resource    = oci_functions_application.exporter[0].id
      service     = "functions"
      source_type = "OCISERVICE"
    }
  }
}

resource "oci_monitoring_alarm" "function_errors" {
  count = local.enabled ? 1 : 0

  compartment_id        = var.compartment_id
  destinations          = [oci_ons_notification_topic.operational_alerts[0].id]
  display_name          = "${var.resource_name_prefix}-function-errors"
  is_enabled            = var.enable_alarm_actions
  metric_compartment_id = var.compartment_id
  namespace             = "oci_faas"
  query                 = "FunctionResponseCount[5m]{resourceId = \"${oci_functions_function.exporter[0].id}\", responseType = \"Error\"}.sum() > 0"
  severity              = "CRITICAL"
  message_format        = "RAW"
  body                  = "The Splunk evidence exporter Function returned an error. Review service logs and the DLQ before any replay."
  freeform_tags         = var.freeform_tags
}

resource "oci_monitoring_alarm" "governed_detection" {
  for_each = local.enabled ? local.governed_detection_alarm_ids : toset([])

  compartment_id        = var.compartment_id
  destinations          = [oci_ons_notification_topic.evidence[0].id]
  display_name          = "${var.resource_name_prefix}-${each.value}"
  is_enabled            = false
  metric_compartment_id = var.log_analytics_compartment_id
  namespace             = var.log_analytics_metric_namespace
  query                 = "DetectionSignal[5m]{detectionId = \"${each.value}\"}.sum() > 0"
  severity              = "CRITICAL"
  message_format        = "RAW"
  body                  = "Governed Log Analytics detection alarm; keep disabled until metric and exporter validation pass."
  freeform_tags         = var.freeform_tags
}

resource "oci_monitoring_alarm" "exporter_delivery_failures" {
  count = local.enabled ? 1 : 0

  compartment_id        = var.compartment_id
  destinations          = [oci_ons_notification_topic.operational_alerts[0].id]
  display_name          = "${var.resource_name_prefix}-delivery-failures"
  is_enabled            = var.enable_alarm_actions
  metric_compartment_id = var.compartment_id
  namespace             = var.exporter_telemetry_namespace
  query                 = "DeliveryFailed[5m].sum() > 0"
  severity              = "CRITICAL"
  message_format        = "RAW"
  body                  = "Splunk evidence exporter delivery failed; review Function logs and DLQ."
  freeform_tags         = var.freeform_tags
}
