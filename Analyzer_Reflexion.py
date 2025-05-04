#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import boto3
import os
import pandas as pd
from io import StringIO
import json
import requests
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo  # Added for EST conversion
import math  
from pandas.errors import EmptyDataError  
 
print("NetGuard Analyzer started successfully.")
 
# S3 client
s3 = boto3.client('s3')
 
# Environment Variables
CERT_BUCKET = os.environ['CERT_BUCKET']
CERT_KEY = os.environ['CERT_KEY']
CHUNKS_BUCKET = os.environ['CHUNKS_BUCKET']
SENTINEL_LOG_BUCKET = os.environ['SENTINEL_LOG_BUCKET']
ANALYZED_CHUNKS_BUCKET = os.environ['ANALYZED_CHUNKS_BUCKET']
SECURE_GPT_ENDPOINT = os.environ['SECURE_GPT_ENDPOINT']
SECURE_GPT_API_KEY = os.environ['SECURE_GPT_API_KEY']
SECURE_GPT_MODEL = os.environ.get('SECURE_GPT_MODEL', 'secure-gpt-model')
 
# Optional fields in the network traffic data that may appear and be appended to the prompt
optional_network_fields = [
    "bytessent",
    "bytesreceived",
    "failedconnectionattempts",
    "unusualpacketfrequency",
    "portscanningbehavior",
    "protocolviolations"
]
 
def download_cert():
    """
    Downloads the certificate file from S3 to /tmp/cert.pem
    so we can use it when verifying SSL connections to Secure GPT.
    """
    local_cert_path = '/tmp/cert.pem'
    print(f"[DEBUG] Downloading cert from s3://{CERT_BUCKET}/{CERT_KEY} to {local_cert_path}")
    s3.download_file(CERT_BUCKET, CERT_KEY, local_cert_path)
    return local_cert_path
 
def read_csv_from_s3(bucket, key):
    """
    Reads a CSV file from the specified S3 bucket/key into a Pandas DataFrame.
    """
    print(f"[DEBUG] Reading CSV from s3://{bucket}/{key}")
    obj = s3.get_object(Bucket=bucket, Key=key)
    content = obj['Body'].read().decode('utf-8')
    return pd.read_csv(StringIO(content))
 
def save_csv_to_s3(df, bucket, key):
    """
    Saves a Pandas DataFrame to a CSV file in the specified S3 bucket/key.
    """
    print(f"[DEBUG] Saving CSV to s3://{bucket}/{key}")
    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False)
    s3.put_object(Bucket=bucket, Key=key, Body=csv_buffer.getvalue())
    print("[DEBUG] Successfully saved CSV to S3.")
 
def get_latest_sentinel_file(bucket):
    """
    Returns the key of the latest (most recently modified) file (CSV or JSON) in the Sentinel logs bucket.
    If no valid file is found, logs a warning and returns None.
    """
    print(f"[DEBUG] Listing CSV files in sentinel bucket: {bucket}")
    response = s3.list_objects_v2(Bucket=bucket)
    valid_files = [obj for obj in response.get('Contents', [])
                   if obj['Key'].endswith('.csv') or obj['Key'].endswith('.json')]
    if not valid_files:
        print("[WARNING] No sentinel log CSV files found in sentinel log bucket.")
        return None
    latest_file = sorted(valid_files, key=lambda x: x['LastModified'], reverse=True)[0]['Key']
    print(f"[DEBUG] Latest sentinel log file: {latest_file}")
    return latest_file
 
def read_sentinel_file(bucket, key):
    """
    Reads a sentinel log file (CSV or JSON) from the specified S3 bucket/key into a Pandas DataFrame.
    """
    print(f"[DEBUG] Reading sentinel file from s3://{bucket}/{key}")
    obj = s3.get_object(Bucket=bucket, Key=key)
    content = obj['Body'].read().decode('utf-8')
    if key.lower().endswith('.csv'):
        return pd.read_csv(StringIO(content))
    elif key.lower().endswith('.json'):
        return pd.read_json(StringIO(content))
    else:
        raise ValueError("[DEBUG] Unsupported file format for sentinel logs.")
 
def call_secure_gpt(prompt, cert_path):
    """
    Calls the Secure GPT endpoint using a custom SSL cert if necessary.
    Expects a JSON response containing 'generated_text'.
    """
    print("[DEBUG] Invoking Secure GPT endpoint.")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SECURE_GPT_API_KEY}"
    }
    data = {
        "inputs": prompt,
        "parameters": {
            "temperature": 0.1,
            "max_new_tokens": 500
        }
    }
    response = requests.post(SECURE_GPT_ENDPOINT, headers=headers, json=data, verify=cert_path)
    response.raise_for_status()
    json_resp = response.json()
    if "generated_text" not in json_resp:
        raise ValueError("[DEBUG] Secure GPT response missing 'generated_text'")
    return json_resp["generated_text"]
 
def build_network_prompt(traffic_row):
    """
    Constructs a base prompt for the network traffic data.
    """
    prompt = f"""
You are a cybersecurity analyst trained on NIST SP 800-53 Revision 5 controls.
Analyze the following network traffic for potential threats, determining the most relevant NIST SP 800-53 Rev 5 control(s) if any anomalies exist.
 
Network Traffic:
- Source IP: {traffic_row['sourceip']}
- Destination IP: {traffic_row['destinationip']}
- Source Port: {traffic_row['sourceport']}
- Destination Port: {traffic_row['destinationport']}
- Protocol: {traffic_row['protocol']}
- Packet Size: {traffic_row['packetsize']}
- Flags: {traffic_row['flags']}
- Connection Status: {traffic_row['connectionstatus']}
"""
    for field in optional_network_fields:
        if field in traffic_row and pd.notnull(traffic_row[field]):
            prompt += f"- {field.capitalize()}: {traffic_row[field]}\n"
 
    prompt += """
Severity Guidelines:
- Low: Traffic is normal, with no significant anomalies or suspicious behavior.
- Medium: Minor anomalies or moderately suspicious behaviors observed.
- High: Significant anomalies strongly suggesting malicious activity.
- Critical: Clear evidence of an ongoing, damaging attack.
 
Before finalizing your answer, work very precisely on the data and verify your analysis carefully.
Respond strictly in this JSON format (no extra text):
{
  "ThreatSeverity": "Critical | High | Medium | Low",
  "ActionTaken": "Mitigation recommendation",
  "ThreatExplanation": "Brief explanation for the threat classification",
  "NISTReference": "List only the relevant NIST control(s) (e.g., SI-3, IR-4, RA-5, SC-7)"
}
"""
    return prompt
 
def lambda_handler(event, context):
    """
    Lambda handler for the Analyzer.
    Triggered by an event containing a 'chunk_key' (extracted either from an S3 event structure or directly in the payload).
    Reads the chunk from CHUNKS_BUCKET, retrieves the latest Sentinel logs, and for each network record:
      - Attempts to match Sentinel logs by IP.
      - In the matched scenario, uses Sentinel data and instructs Secure GPT to produce threat metrics and a self-reflection.
      - In the unmatched scenario, instructs Secure GPT to analyze solely based on the traffic data and derive dynamic anomaly details and a self-reflection.
    The enriched output is written as a CSV file to ANALYZED_CHUNKS_BUCKET (under "temp_analysis/"), the processed chunk file is deleted,
    and the S3 key for the enriched output is returned.
    """
    print("[DEBUG] NetGuard Analyzer invoked with event:", event)
    print(f"[DEBUG] CERT_BUCKET: {CERT_BUCKET}")
    print(f"[DEBUG] CERT_KEY: {CERT_KEY}")
    print(f"[DEBUG] CHUNKS_BUCKET: {CHUNKS_BUCKET}")
    print(f"[DEBUG] SENTINEL_LOG_BUCKET: {SENTINEL_LOG_BUCKET}")
    print(f"[DEBUG] ANALYZED_CHUNKS_BUCKET: {ANALYZED_CHUNKS_BUCKET}")
    print(f"[DEBUG] SECURE_GPT_ENDPOINT: {SECURE_GPT_ENDPOINT}")
 
    cert_path = download_cert()
   
    # Extract chunk_key from the event (supports S3 event structure or direct payload)
    if "Records" in event:
        try:
            chunk_key = event["Records"][0]["s3"]["object"]["key"]
            print(f"[DEBUG] Extracted chunk_key from S3 event: {chunk_key}")
        except (KeyError, IndexError) as e:
            raise ValueError("[DEBUG] Unable to extract chunk_key from S3 event structure.") from e
    elif "chunk_key" in event:
        chunk_key = event["chunk_key"]
        print(f"[DEBUG] chunk_key provided: {chunk_key}")
    else:
        raise ValueError("[DEBUG] No chunk_key provided in the event.")
   
    print("[DEBUG] Reading chunk from S3...")
    network_df = read_csv_from_s3(CHUNKS_BUCKET, chunk_key)
    print(f"[DEBUG] Chunk DataFrame shape: {network_df.shape}")
   
    network_df.columns = [c.strip().replace(" ", "").lower() for c in network_df.columns]
    print(f"[DEBUG] Normalized columns: {network_df.columns.tolist()}")
   
    # Retrieve the latest Sentinel log
    sentinel_file = get_latest_sentinel_file(SENTINEL_LOG_BUCKET)
    if sentinel_file is None:
        print("[WARNING] No sentinel log file present. Proceeding with unmatched scenario only.")
        sentinel_df = pd.DataFrame()
        matching_possible = False
    else:
        sentinel_df = read_sentinel_file(SENTINEL_LOG_BUCKET, sentinel_file)
        sentinel_df.columns = [c.strip().replace(" ", "").lower() for c in sentinel_df.columns]
        print(f"[DEBUG] Read sentinel logs file {sentinel_file} with shape: {sentinel_df.shape}")
        sentinel_df = sentinel_df.fillna("N/A")
        if sentinel_df.empty:
            print("[WARNING] Sentinel log file is present but empty. Proceeding with unmatched scenario only.")
            matching_possible = False
        else:
            required_sentinel_cols = ['sourceip', 'destinationip']
            missing_sentinel_cols = [col for col in required_sentinel_cols if col not in sentinel_df.columns]
            if missing_sentinel_cols:
                print(f"[WARNING] Sentinel logs missing essential columns: {missing_sentinel_cols}.")
                matching_possible = False
            else:
                matching_possible = True
            missing_port_cols = [col for col in ['sourceport', 'destinationport'] if col not in sentinel_df.columns]
            if missing_port_cols:
                print(f"[WARNING] Sentinel logs missing optional port fields: {missing_port_cols}.")
            expected_generic_cols = ['logid', 'anomalytype', 'logmessage', 'anomalydescription', 'nistreference', 'loglevel']
            missing_generic_cols = [col for col in expected_generic_cols if col not in sentinel_df.columns]
            if missing_generic_cols:
                print(f"[WARNING] Sentinel logs missing generic fields: {missing_generic_cols}. Using default values for these fields.")
   
    output_logs = []
   
    # Process each record in the network chunk
    for _, traffic_row in network_df.iterrows():
        base_prompt = build_network_prompt(traffic_row)
       
        if matching_possible:
            matching_sentinel = sentinel_df[
                (sentinel_df['sourceip'] == traffic_row['sourceip']) &
                (sentinel_df['destinationip'] == traffic_row['destinationip'])
            ]
        else:
            matching_sentinel = pd.DataFrame()
       
        if not matching_sentinel.empty:
            # Matched scenario
            for _, anomaly_row in matching_sentinel.iterrows():
                system_log_id = anomaly_row.get('logid', 'N/A') if ('logid' in sentinel_df.columns and anomaly_row.get('logid') not in [None, "", "N/A"]) else "N/A"
                print("[DEBUG] Using updated dynamic prompt for matched scenario.")
                prompt = base_prompt + f"""
Sentinel Anomaly Correlation:
Anomaly identified in Sentinel Logs. Correlate this with the traffic details above.
 
Sentinel Log Data:
- Anomaly Type: {anomaly_row.get('anomalytype', 'N/A')}
- Log Message: {anomaly_row.get('logmessage', 'N/A')}
- Description: {anomaly_row.get('anomalydescription', 'N/A')}
- NIST Reference: {anomaly_row.get('nistreference', 'N/A')}
- Log Level: {anomaly_row.get('loglevel', 'N/A')}
 
Remember the severity guidelines: Low, Medium, High, or Critical.
Additionally, provide a brief Reflection summarizing your reasoning and any observed uncertainties.
Respond strictly in the following JSON format (no extra text):
{{
  "ThreatSeverity": "Critical | High | Medium | Low",
  "ActionTaken": "Mitigation recommendation",
  "ThreatExplanation": "Brief explanation for the threat classification",
  "NISTReference": "Relevant NIST control(s)",
  "AnomalyType": "Dynamic anomaly type based on your analysis, or 'None' if normal",
  "AnomalyDescription": "Dynamic description detailing the anomaly",
  "Reflection": "A brief summary of your reasoning process, key factors, and potential improvements"
}}
"""
                print("[DEBUG] Calling Secure GPT for matched record.")
                gpt_resp = call_secure_gpt(prompt, cert_path)
                try:
                    gpt_decision = json.loads(gpt_resp)
                    classification = {
                        "ThreatSeverity": gpt_decision.get("ThreatSeverity", "Medium"),
                        "ActionTaken": gpt_decision.get("ActionTaken", "Manual review"),
                        "ThreatExplanation": gpt_decision.get("ThreatExplanation", ""),
                        "NISTReference": gpt_decision.get("NISTReference", ""),
                        "AnomalyType": gpt_decision.get("AnomalyType", ""),
                        "AnomalyDescription": gpt_decision.get("AnomalyDescription", ""),
                        "Reflection": gpt_decision.get("Reflection", "")
                    }
                except json.JSONDecodeError:
                    classification = {
                        "ThreatSeverity": "Medium", "ActionTaken": "Manual review",
                        "ThreatExplanation": "", "NISTReference": "",
                        "AnomalyType": "", "AnomalyDescription": "", "Reflection": ""
                    }
               
                output_logs.append({
                    "Timestamp": datetime.utcnow().isoformat(),
                    "NetworkLogID": f"NETLOG-{uuid.uuid4().hex[:8]}",
                    "LogSystem": "NetGuard",
                    "LogMessage": anomaly_row.get('logmessage', 'N/A'),
                    "LogLevel": anomaly_row.get('loglevel', 'N/A'),
                    "AnomalyType": classification["AnomalyType"] if classification["AnomalyType"] else anomaly_row.get('anomalytype', 'N/A'),
                    "AnomalyDescription": classification["AnomalyDescription"] if classification["AnomalyDescription"] else anomaly_row.get('anomalydescription', 'N/A'),
                    "NISTReference": classification["NISTReference"],
                    "SystemLogID": system_log_id,
                    "SourceIP": traffic_row['sourceip'],
                    "DestinationIP": traffic_row['destinationip'],
                    "SourcePort": traffic_row['sourceport'],
                    "DestinationPort": traffic_row['destinationport'],
                    "ThreatSeverity": classification["ThreatSeverity"],
                    "Action Taken": classification["ActionTaken"],
                    "threatexplanation": classification["ThreatExplanation"],
                    "Reflection": classification["Reflection"],
                    "TrueSeverity": traffic_row.get('trueseverity', 'N/A')
                })
        else:
            # Unmatched scenario
            print("[DEBUG] Using updated dynamic prompt for unmatched scenario.")
            prompt = base_prompt + f"""
There is no matching anomaly from Sentinel Logs for this record.
Please analyze the provided network traffic data very precisely and determine if any inherent anomaly or suspicious behavior exists.
Based solely on this traffic data, derive the appropriate ThreatSeverity and generate a detailed, data-driven anomaly assessment.
In your response, dynamically determine the AnomalyType and provide an AnomalyDescription that accurately reflects the anomaly detected (or indicate 'None'/'Low Risk' if the data is clean).
Furthermore, provide a Reflection summarizing your reasoning: explain the key factors you considered, any uncertainties, and potential improvements for future analysis.
If the data is clean, classify it as Low.
Work precisely on the data and do not rely on pre-defined static text.
Respond strictly in the following JSON format (no extra text):
{{
  "ThreatSeverity": "Critical | High | Medium | Low",
  "ActionTaken": "Mitigation recommendation",
  "ThreatExplanation": "Brief explanation for the threat classification",
  "NISTReference": "Relevant NIST control(s)",
  "AnomalyType": "Dynamic anomaly type based on your analysis, or 'None' if the record is clean",
  "AnomalyDescription": "Dynamic description detailing the anomaly",
  "Reflection": "A brief summary of your reasoning process, key factors, and potential improvements"
}}
"""
            print("[DEBUG] Calling Secure GPT for unmatched record.")
            gpt_resp = call_secure_gpt(prompt, cert_path)
            try:
                gpt_decision = json.loads(gpt_resp)
                classification = {
                    "ThreatSeverity": gpt_decision.get("ThreatSeverity", "Low"),
                    "ActionTaken": gpt_decision.get("ActionTaken", "Monitor traffic"),
                    "ThreatExplanation": gpt_decision.get("ThreatExplanation", ""),
                    "NISTReference": gpt_decision.get("NISTReference", ""),
                    "AnomalyType": gpt_decision.get("AnomalyType", ""),
                    "AnomalyDescription": gpt_decision.get("AnomalyDescription", ""),
                    "Reflection": gpt_decision.get("Reflection", "")
                }
            except json.JSONDecodeError:
                classification = {
                    "ThreatSeverity": "Low", "ActionTaken": "Monitor traffic",
                    "ThreatExplanation": "", "NISTReference": "",
                    "AnomalyType": "None", "AnomalyDescription": "", "Reflection": ""
                }
           
            output_logs.append({
                "Timestamp": datetime.utcnow().isoformat(),
                "NetworkLogID": f"NETLOG-{uuid.uuid4().hex[:8]}",
                "LogSystem": "NetGuard",
                "LogMessage": "Anomaly detection via traffic analysis",
                "LogLevel": classification["ThreatSeverity"],
                "AnomalyType": classification["AnomalyType"],
                "AnomalyDescription": classification["AnomalyDescription"],
                "NISTReference": classification["NISTReference"],
                "SystemLogID": "N/A",
                "SourceIP": traffic_row['sourceip'],
                "DestinationIP": traffic_row['destinationip'],
                "SourcePort": traffic_row['sourceport'],
                "DestinationPort": traffic_row['destinationport'],
                "ThreatSeverity": classification["ThreatSeverity"],
                "Action Taken": classification["ActionTaken"],
                "threatexplanation": classification["ThreatExplanation"],
                "Reflection": classification["Reflection"],
                "TrueSeverity": traffic_row.get('trueseverity', 'N/A')
            })
   
    # Write the enriched output to S3 in the "temp_analysis/" folder
    est_zone = ZoneInfo("America/New_York")
    timestamp_est_str = datetime.now(est_zone).strftime("%Y-%m-%d_%H-%M-%S_%Z")
    try:
        chunk_index = chunk_key.split("_chunk")[-1].split(".csv")[0]
    except Exception as e:
        print(f"[DEBUG] Could not extract chunk index: {e}")
        chunk_index = "1"
    partial_filename = f"temp_analysis/enriched_{timestamp_est_str}_Analysed{chunk_index}.csv"
   
    df_output = pd.DataFrame(output_logs)
    df_output = df_output.fillna("N/A")
   
    save_csv_to_s3(df_output, ANALYZED_CHUNKS_BUCKET, partial_filename)
    print(f"[DEBUG] Wrote partial enriched output to s3://{ANALYZED_CHUNKS_BUCKET}/{partial_filename}")
   
    print(f"[DEBUG] Deleting the chunk file from s3://{CHUNKS_BUCKET}/{chunk_key}")
    try:
        s3.delete_object(Bucket=CHUNKS_BUCKET, Key=chunk_key)
        print("[DEBUG] Successfully deleted the chunk file.")
    except Exception as e:
        print(f"[ERROR] Could not delete chunk file: {e}")
   
    return {
        "statusCode": 200,
        "partial_output_key": partial_filename,
        "message": f"Processed {len(network_df)} rows from chunk: {chunk_key}"
    }
 
 
 

