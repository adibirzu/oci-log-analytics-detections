resource "null_resource" "deploy_log_sources" {
  count = var.deploy_log_sources ? 1 : 0

  provisioner "local-exec" {
    command     = "python3 ../scripts/setup_log_sources.py"
    working_dir = path.module

    environment = {
      OCI_TENANCY_ID     = var.tenancy_ocid
      OCI_COMPARTMENT_ID = var.compartment_id
      LA_NAMESPACE       = local.la_namespace
      LA_LOG_GROUP_ID    = local.effective_log_group_id
    }
  }

  depends_on = [oci_log_analytics_log_analytics_log_group.soc_detection]

  triggers = {
    log_group_id = local.effective_log_group_id
  }
}

resource "null_resource" "deploy_dashboards" {
  count = var.deploy_dashboards ? 1 : 0

  provisioner "local-exec" {
    command     = var.deploy_dashboard_cleanup ? "python3 ../scripts/deploy_dashboard.py --cleanup" : "python3 ../scripts/deploy_dashboard.py"
    working_dir = path.module

    environment = {
      OCI_TENANCY_ID     = var.tenancy_ocid
      OCI_COMPARTMENT_ID = var.compartment_id
      LA_NAMESPACE       = local.la_namespace
      LA_LOG_GROUP_ID    = local.effective_log_group_id
    }
  }

  depends_on = [
    oci_log_analytics_log_analytics_log_group.soc_detection,
    null_resource.deploy_log_sources,
  ]

  triggers = {
    log_group_id = local.effective_log_group_id
  }
}

resource "null_resource" "ingest_test_data" {
  count = var.ingest_test_data ? 1 : 0

  provisioner "local-exec" {
    command     = "python3 ../scripts/ingest_test_data.py --mode direct"
    working_dir = path.module

    environment = {
      OCI_TENANCY_ID     = var.tenancy_ocid
      OCI_COMPARTMENT_ID = var.compartment_id
      LA_NAMESPACE       = local.la_namespace
      LA_LOG_GROUP_ID    = local.effective_log_group_id
    }
  }

  depends_on = [
    oci_log_analytics_log_analytics_log_group.soc_detection,
    null_resource.deploy_log_sources,
    null_resource.deploy_dashboards,
  ]

  triggers = {
    log_group_id = local.effective_log_group_id
  }
}
