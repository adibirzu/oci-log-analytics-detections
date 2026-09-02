variable "enable_splunk_evidence_exporter" {
  type        = bool
  description = "Create the optional Splunk evidence exporter resources"
  default     = false
}

variable "enable_alarm_actions" {
  type        = bool
  description = "Enable the reviewed OCI Functions error alarm"
  default     = false
}

variable "enable_notification_subscription" {
  type        = bool
  description = "Create the reviewed exact Notifications-to-Function subscription"
  default     = false
}

variable "log_analytics_metric_namespace" {
  type        = string
  description = "Governed Monitoring metric namespace for Log Analytics detection signals"
  default     = "oci_log_analytics_detections"
}

variable "exporter_telemetry_namespace" {
  type        = string
  description = "Governed Monitoring metric namespace for exporter operational telemetry"
  default     = "oci_log_analytics_splunk_exporter"
}

variable "compartment_id" {
  type        = string
  description = "OCID of the compartment that owns the scoped exporter resources"
  default     = ""
}

variable "log_analytics_compartment_id" {
  type        = string
  description = "OCID of the compartment the Function may query"
  default     = ""
}

variable "log_analytics_namespace" {
  type        = string
  description = "Trusted Log Analytics tenancy namespace; never taken from alarm payloads"
  default     = ""
}

variable "splunk_alarm_ids" {
  type        = map(string)
  description = "Operator-configured map of governed detection binding keys to exact Monitoring alarm OCIDs"
  default     = {}
  sensitive   = true
}

variable "log_analytics_compartment_in_subtree" {
  type        = bool
  description = "Whether bounded queries include subcompartments"
  default     = false
}

variable "object_storage_namespace" {
  type        = string
  description = "Existing Object Storage namespace for checkpoint and DLQ access"
  default     = ""
}

variable "existing_state_bucket_name" {
  type        = string
  description = "Existing private state bucket name; leave empty to create a scoped bucket"
  default     = ""
}

variable "existing_dlq_bucket_name" {
  type        = string
  description = "Existing private DLQ bucket name; leave empty to create a scoped bucket"
  default     = ""
}

variable "resource_name_prefix" {
  type        = string
  description = "Non-confidential prefix for exporter resource display names"
  default     = "splunk-evidence-exporter"
}

variable "function_subnet_ids" {
  type        = list(string)
  description = "Existing subnet OCIDs for the Function application; no VCN is created"
  default     = []
}

variable "function_network_security_group_ids" {
  type        = list(string)
  description = "Existing network security group OCIDs for reviewed Function egress"
  default     = []
}

variable "function_image" {
  type        = string
  description = "Reviewed OCI Registry image reference containing the exporter handler"
  default     = ""
}

variable "function_image_digest" {
  type        = string
  description = "Required immutable sha256 digest for the reviewed exporter image when enabled"
  default     = ""
}

variable "function_memory_in_mbs" {
  type        = number
  description = "Maximum Function memory in MiB"
  default     = 512
}

variable "function_timeout_in_seconds" {
  type        = number
  description = "Bounded Function execution timeout"
  default     = 120

  validation {
    condition     = var.function_timeout_in_seconds >= 30 && var.function_timeout_in_seconds <= 300
    error_message = "Function timeout must be between 30 and 300 seconds."
  }
}

variable "function_log_retention_days" {
  type        = number
  description = "OCI Logging retention in supported 30-day increments"
  default     = 30

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180], var.function_log_retention_days)
    error_message = "Function log retention must be a supported 30-day increment from 30 to 180."
  }
}

variable "splunk_hec_secret_id" {
  type        = string
  description = "OCID of an existing OCI Vault secret containing the Splunk HEC credential"
  default     = ""
  sensitive   = true

  validation {
    condition     = var.splunk_hec_secret_id == "" || can(regex("^ocid1\\.vaultsecret\\.", var.splunk_hec_secret_id))
    error_message = "Provide an existing OCI Vault secret OCID; never provide a secret value."
  }
}

variable "splunk_hec_url" {
  type        = string
  description = "Reviewed HTTPS Splunk HEC /services/collector/event endpoint without userinfo, query, fragment, or credential material"
  default     = ""

  validation {
    condition     = var.splunk_hec_url == "" || can(regex("^https://[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/services/collector/event$", var.splunk_hec_url))
    error_message = "Use an HTTPS authority and the exact /services/collector/event path, without userinfo, query, or fragment."
  }
}

variable "splunk_hec_index" {
  type        = string
  description = "Reviewed Splunk index for evidence events"
  default     = ""
}

variable "splunk_hec_sourcetype" {
  type        = string
  description = "Splunk sourcetype for evidence events"
  default     = "oci:logan:detection"
}

variable "splunk_hec_acknowledgement_mode" {
  type        = string
  description = "Exporter HEC acknowledgement behavior"
  default     = "response"

  validation {
    condition     = contains(["response", "indexer_ack"], var.splunk_hec_acknowledgement_mode)
    error_message = "HEC acknowledgement mode must be response or indexer_ack."
  }
}

variable "splunk_hec_timeout_seconds" {
  type        = number
  description = "Per-request HEC timeout within the runtime ceiling"
  default     = 10

  validation {
    condition     = var.splunk_hec_timeout_seconds >= 1 && var.splunk_hec_timeout_seconds <= 60
    error_message = "HEC timeout must be between 1 and 60 seconds."
  }
}

variable "splunk_evidence_max_rows" {
  type        = number
  description = "Maximum Log Analytics rows per bounded query"
  default     = 1000

  validation {
    condition     = var.splunk_evidence_max_rows >= 1 && var.splunk_evidence_max_rows <= 10000
    error_message = "Maximum evidence rows must be between 1 and 10000."
  }
}

variable "splunk_hec_max_batch_events" {
  type        = number
  description = "Maximum events per HEC batch"
  default     = 100

  validation {
    condition     = var.splunk_hec_max_batch_events >= 1 && var.splunk_hec_max_batch_events <= 1000
    error_message = "Maximum HEC batch events must be between 1 and 1000."
  }
}

variable "splunk_evidence_max_attempts" {
  type        = number
  description = "Maximum delivery attempts per batch"
  default     = 4

  validation {
    condition     = var.splunk_evidence_max_attempts >= 1 && var.splunk_evidence_max_attempts <= 10
    error_message = "Maximum delivery attempts must be between 1 and 10."
  }
}

variable "splunk_evidence_lookback_seconds" {
  type        = number
  description = "Initial evidence query lookback"
  default     = 900
}

variable "splunk_evidence_overlap_seconds" {
  type        = number
  description = "Checkpoint overlap for at-least-once delivery"
  default     = 120
}

variable "splunk_evidence_max_window_seconds" {
  type        = number
  description = "Maximum bounded Log Analytics query window"
  default     = 7200
}

variable "state_previous_version_retention_days" {
  type        = number
  description = "Days to retain superseded checkpoint object versions"
  default     = 30
}

variable "dlq_retention_days" {
  type        = number
  description = "Days to retain current DLQ records for reviewed replay"
  default     = 90
}

variable "dlq_previous_version_retention_days" {
  type        = number
  description = "Days to retain superseded DLQ object versions"
  default     = 30
}

variable "freeform_tags" {
  type        = map(string)
  description = "Optional non-confidential tags for exporter resources"
  default     = {}
}
