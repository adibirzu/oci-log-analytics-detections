import oci
import json
import datetime
import random

COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaaghzlt3b6zl3nb7fsyh4nuiuzsuh4zzghfxmtfvvk4byylbvh56ba"

def generate_audit_log(namespace):
    # com.oraclecloud.identity.authentication.login
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    return {
        "datetime": event_time,
        "log_source": "OCI Audit Logs",
        "fields": {
            "Event Type": "com.oraclecloud.identity.authentication.login",
            "Status": "Success" if random.random() > 0.2 else "Failure",
            "User": f"user_{random.randint(1,10)}@example.com",
            "Client Host": f"192.168.1.{random.randint(1,254)}",
            "Action": "POST",
            "Message": "User logged in successfully"
        }
    }

def ingest_data():
    config = oci.config.from_file()
    log_analytics_client = oci.log_analytics.LogAnalyticsClient(config)
    
    namespace = log_analytics_client.list_namespaces(compartment_id=COMPARTMENT_ID).data.items[0].namespace_name
    print(f"Ingesting test data into Namespace: {namespace}")
    
    # In OCI, ingesting "custom" data into a predefined source like OCI Audit Logs 
    # usually requires uploading to an Object Storage bucket or using the Upload API
    # with a specific Log Source and Entity.
    
    print("To see data in the dashboard, please ensure OCI Audit Logs are enabled in your tenancy.")
    print("The OCI Audit service automatically pushes logs to Logging, which can be ingested into Log Analytics.")
    print("
Simulating data ingestion (log message output):")
    for _ in range(5):
        log = generate_audit_log(namespace)
        print(json.dumps(log, indent=2))

if __name__ == "__main__":
    ingest_data()
