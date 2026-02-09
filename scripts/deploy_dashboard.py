import oci
import json
import os

TENANCY_ID = "ocid1.tenancy.oc1..aaaaaaaaxzpxbcag7zgamh2erlggqro3y63tvm2rbkkjz4z2zskvagupiz7a"
COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaaghzlt3b6zl3nb7fsyh4nuiuzsuh4zzghfxmtfvvk4byylbvh56ba"
PROJECT_DIR = 'oci-log-analytics-detections'
QUERIES_DIR = os.path.join(PROJECT_DIR, 'queries')

widgets = [
    {"title": "SOC: OCI Console Login Failures", "query_file": "oci_console_login_from_unusual_ip.json"},
    {"title": "SOC: Suspicious Linux Binaries", "query_file": "suspicious_usage_of_netcat.json"},
    {"title": "SOC: Critical IAM Policy Changes", "query_file": "oci_iam_policy_modified.json"},
    {"title": "SOC: Object Storage Public Buckets", "query_file": "oci_object_storage_bucket_made_public.json"},
    {"title": "SOC: VCN Security List Open to World", "query_file": "oci_vcn_security_list_open_to_world.json"},
    {"title": "SOC: SSH Failed Logins Trend", "query_file": "linux_ssh_failed_login.json"}
]

def deploy():
    config = oci.config.from_file()
    md_client = oci.management_dashboard.DashxApisClient(config)
    
    print(f"Deploying Dashboard Components to Compartment: {COMPARTMENT_ID}")

    saved_search_ids = []

    for widget in widgets:
        query_path = os.path.join(QUERIES_DIR, widget['query_file'])
        if not os.path.exists(query_path):
            continue
            
        with open(query_path, 'r') as f:
            rule_data = json.load(f)
            
        search_list = md_client.list_management_saved_searches(
            compartment_id=COMPARTMENT_ID,
            display_name=widget['title']
        ).data.items
        
        if search_list:
            saved_search_ids.append(search_list[0].id)
            continue

        data_config = [{"query": rule_data['query'], "providerName": "log-analytics", "dataSourceId": "loganalytics"}]

        details = oci.management_dashboard.models.CreateManagementSavedSearchDetails(
            display_name=widget['title'],
            description=rule_data.get('description', ''),
            compartment_id=COMPARTMENT_ID,
            is_oob_saved_search=False,
            provider_name="log-analytics",
            provider_version="2.0",
            provider_id="log-analytics",
            type="SEARCH_SHOW_IN_DASHBOARD",
            data_config=data_config,
            metadata_version="2.0",
            widget_template="{}",
            widget_vm="{}",
            screen_image="",
            nls={},
            ui_config={}
        )
        
        try:
            new_search = md_client.create_management_saved_search(details).data
            saved_search_ids.append(new_search.id)
        except Exception as e:
            print(f"  Error creating {widget['title']}: {e}")

    # Create Dashboard
    dashboard_name = "SOC Security Dashboard"
    existing_dash = md_client.list_management_dashboards(compartment_id=COMPARTMENT_ID, display_name=dashboard_name).data.items
    
    if existing_dash:
        print(f"Dashboard '{dashboard_name}' already exists: {existing_dash[0].id}")
        return

    tiles = []
    for i, ss_id in enumerate(saved_search_ids):
        row = i // 2
        col = (i % 2) * 6
        tile = oci.management_dashboard.models.ManagementDashboardTileDetails(
            display_name=widgets[i]['title'],
            saved_search_id=ss_id,
            row=row,
            column=col,
            height=4,
            width=6,
            state="DEFAULT",
            nls={},
            ui_config={},
            data_config=[],
            drilldown_config=[],
            parameters_map={}
        )
        tiles.append(tile)

    dashboard_details = oci.management_dashboard.models.CreateManagementDashboardDetails(
        display_name=dashboard_name,
        description="Dashboard showcasing OCI Log Analytics detection rules for SOC.",
        compartment_id=COMPARTMENT_ID,
        tiles=tiles,
        is_oob_dashboard=False,
        is_show_in_home=True,
        metadata_version="2.0",
        is_show_description=True,
        screen_image="",
        provider_id="management-dashboard",
        provider_name="management-dashboard",
        provider_version="2.0",
        type="NORMAL",
        is_favorite=False,
        nls={},
        ui_config={},
        data_config=[]
    )

    try:
        new_dashboard = md_client.create_management_dashboard(dashboard_details).data
        print(f"\nSuccessfully created Dashboard: {new_dashboard.display_name}")
        print(f"OCID: {new_dashboard.id}")
    except Exception as e:
        print(f"Error creating dashboard: {e}")

if __name__ == "__main__":
    deploy()