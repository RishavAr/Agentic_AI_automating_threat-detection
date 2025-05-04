#!/usr/bin/env python
# coding: utf-8

# In[1]:


import boto3
import os
import pandas as pd
import json
import requests
from io import StringIO
from requests.auth import HTTPBasicAuth
 
print("NetGuard Ticket Generator started successfully.")
 
# Create an S3 client
s3 = boto3.client('s3')
 
def lambda_handler(event, context):
    print("[DEBUG] Ticket Generator invoked.")
   
    # Get final output file key from the event.
    # If not provided, return a Bad Request response immediately.
    final_output_key = event.get("final_output_key")
    if not final_output_key:
        print("[ERROR] final_output_key is not provided in the event.")
        return {
            "statusCode": 400,
            "message": "final_output_key is not provided in the event. Hence, no tickets will be generated."
        }
   
    FINAL_OUTPUT_BUCKET = os.environ["FINAL_OUTPUT_BUCKET"]
   
    print(f"[DEBUG] Reading final output file from s3://{FINAL_OUTPUT_BUCKET}/{final_output_key}")
    obj = s3.get_object(Bucket=FINAL_OUTPUT_BUCKET, Key=final_output_key)
    content = obj['Body'].read().decode('utf-8')
    df = pd.read_csv(StringIO(content))
    print(f"[DEBUG] Loaded final output DataFrame with shape: {df.shape}")
   
    # JIRA configuration from environment variables
    JIRA_API_TOKEN = os.environ["JIRA_API_TOKEN"]
    jira_domain = os.environ["JIRA_DOMAIN"]
    if jira_domain.startswith("https://"):
        jira_domain = jira_domain[len("https://"):]
    JIRA_PROJECT_KEY = os.environ["JIRA_PROJECT_KEY"]
    JIRA_EMAIL = os.environ["JIRA_EMAIL"]
    JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")
   
    ticket_count = 0
    total_threats_found = 0  # Count all high/critical threats
   
 
   
    for index, row in df.iterrows():
        # Retrieve and check the threat severity
        threat_severity = row.get('ThreatSeverity', 'Unknown')
        if threat_severity.lower() not in ['high', 'critical']:
            print(f"[DEBUG] Skipping ticket generation for row {index} due to threat severity: {threat_severity}")
            continue  # Skip ticket generation for non-high/critical severities
       
        # For each high/critical threat, count it
        total_threats_found += 1
             
        # Construct ticket summary and description using row data
        summary = f"Threat detected: {threat_severity} from {row.get('SourceIP', 'N/A')}"
        description = (
            f"Network Traffic Alert:\n"
            f"- Source IP: {row.get('SourceIP', 'N/A')}\n"
            f"- Destination IP: {row.get('DestinationIP', 'N/A')}\n"
            f"- Threat Severity: {threat_severity}\n"
            f"- Action Taken: {row.get('Action Taken', 'N/A')}\n"
            f"- Additional Info: {row.get('threatexplanation', 'N/A')}\n"
        )
        print(f"[DEBUG] Creating ticket for row {index}: Summary: {summary}")
 
        payload = {
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"text": description, "type": "text"}]
                        }
                    ]
                },
                "issuetype": {"name": JIRA_ISSUE_TYPE}
            }
        }
       
        jira_url = f"https://{jira_domain}/rest/api/3/issue"
        auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
        headers = {"Content-Type": "application/json"}
       
        response = requests.post(jira_url, data=json.dumps(payload), headers=headers, auth=auth)
       
        if response.status_code == 201:
            print(f"[DEBUG] Ticket created successfully for row {index}.")
            ticket_count += 1
        elif response.status_code in [401, 403]:
            # Specialized handling for invalid credentials or forbidden
            print(f"[ERROR] Authentication failed (HTTP {response.status_code}). No tickets will be created for this run.")
            # We can break out immediately since further tickets won't succeed:
            break
        else:
            print(f"[ERROR] Failed to create ticket for row {index}: {response.text}")
   
    final_message = (
        f"Ticket generation complete. {ticket_count} ticket(s) created out of "
        f"{total_threats_found} high/critical threats. "
        f"{total_threats_found - ticket_count} threat(s) skipped due to ticket limit or auth error."
    )
    print(f"[DEBUG] {final_message}")
    return {
        "statusCode": 200,
        "message": final_message
    }
 
 
 
 


# In[ ]:




