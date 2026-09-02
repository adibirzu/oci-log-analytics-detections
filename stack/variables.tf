# --- General Configuration ---

variable "compartment_id" {
  type        = string
  description = "OCID of the compartment where resources will be created"
}

variable "tenancy_ocid" {
  type        = string
  description = "OCID of the tenancy (auto-populated by ORM)"
}

variable "region" {
  type        = string
  description = "OCI region for deployment (auto-populated by ORM)"
}

# --- Log Analytics ---

variable "log_group_name" {
  type        = string
  description = "Name of the Log Analytics log group"
  default     = "soc-detection-test-logs"
}

variable "log_group_description" {
  type        = string
  description = "Description for the Log Analytics log group"
  default     = "Log group for SOC detection rules testing and validation"
}

# --- Streaming ---

variable "stream_pool_id" {
  type        = string
  description = "OCID of an existing stream pool (leave empty to use compartment directly)"
  default     = ""
}

variable "stream_partitions" {
  type        = number
  description = "Number of partitions per stream"
  default     = 1

  validation {
    condition     = var.stream_partitions >= 1 && var.stream_partitions <= 10
    error_message = "Stream partitions must be between 1 and 10."
  }
}

variable "stream_retention_hours" {
  type        = number
  description = "Message retention period in hours"
  default     = 24

  validation {
    condition     = var.stream_retention_hours >= 24 && var.stream_retention_hours <= 168
    error_message = "Retention hours must be between 24 and 168."
  }
}

# --- Provisioning Options ---

variable "deploy_log_sources" {
  type        = bool
  description = "Create custom LA fields, parsers, and log sources"
  default     = true
}

variable "deploy_dashboards" {
  type        = bool
  description = "Deploy SOC detection dashboards and saved searches"
  default     = true
}

variable "deploy_dashboard_cleanup" {
  type        = bool
  description = "Remove existing SOC dashboards before deploying new ones"
  default     = true
}

variable "ingest_test_data" {
  type        = bool
  description = "Upload test attack logs for validation"
  default     = false
}

# --- Optional Splunk Evidence Exporter ---

variable "enable_splunk_evidence_exporter" {
  type        = bool
  description = "Create the reviewed Splunk evidence exporter resources"
  default     = false
}

variable "enable_splunk_evidence_exporter_alarm_actions" {
  type        = bool
  description = "Enable exporter alarm actions after a separate operator review"
  default     = false
}

variable "enable_splunk_evidence_exporter_subscription" {
  type        = bool
  description = "Enable the exact Notifications-to-Function subscription after review"
  default     = false
}

variable "splunk_evidence_exporter_hec_secret_id" {
  type        = string
  description = "OCID of an existing OCI Vault secret containing the Splunk HEC credential"
  default     = ""
  sensitive   = true

  validation {
    condition     = var.splunk_evidence_exporter_hec_secret_id == "" || can(regex("^ocid1\\.vaultsecret\\.", var.splunk_evidence_exporter_hec_secret_id))
    error_message = "Provide an existing OCI Vault secret OCID; never provide a secret value."
  }
}

variable "splunk_evidence_exporter_object_storage_namespace" {
  type        = string
  description = "Existing Object Storage namespace for exporter state and DLQ"
  default     = ""
}

variable "splunk_evidence_exporter_existing_state_bucket_name" {
  type        = string
  description = "Existing private state bucket name; leave empty to create one"
  default     = ""
}

variable "splunk_evidence_exporter_existing_dlq_bucket_name" {
  type        = string
  description = "Existing private DLQ bucket name; leave empty to create one"
  default     = ""
}

variable "splunk_evidence_exporter_function_subnet_ids" {
  type        = list(string)
  description = "Existing subnet OCIDs for the Function application; no VCN is created"
  default     = []
}

variable "splunk_evidence_exporter_function_nsg_ids" {
  type        = list(string)
  description = "Existing NSG OCIDs governing reviewed Function egress"
  default     = []
}

variable "splunk_evidence_exporter_function_image" {
  type        = string
  description = "Reviewed OCI Registry image reference containing the exporter handler"
  default     = ""
}

variable "splunk_evidence_exporter_function_image_digest" {
  type        = string
  description = "Optional immutable digest for the reviewed exporter image"
  default     = ""
}

variable "splunk_evidence_exporter_hec_url" {
  type        = string
  description = "Reviewed HTTPS Splunk HEC /services/collector/event endpoint without userinfo, query, fragment, or credential material"
  default     = ""

  validation {
    condition     = var.splunk_evidence_exporter_hec_url == "" || can(regex("^https://[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/services/collector/event$", var.splunk_evidence_exporter_hec_url))
    error_message = "Use an HTTPS authority and the exact /services/collector/event path, without userinfo, query, or fragment."
  }
}

variable "splunk_evidence_exporter_hec_index" {
  type        = string
  description = "Reviewed Splunk index for evidence events"
  default     = ""
}
