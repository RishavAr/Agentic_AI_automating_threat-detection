# DAEN-690-NetGuard
# NetGuard – Agentic AI for Real‑Time Network Traffic Monitoring & Proactive Threat Mitigation
> **Course:** DAEN 690 • Spring 2025  
> **Team:** Artum Khorshid · Durga Prasad Esampelly · Prudhvi Sandeep Mudidana · Ravi Teja Talluri · Rishav Aryan · Samhita Sarikonda

NetGuard is a serverless, multi‑agent cybersecurity platform that **ingests live network traffic, enriches it with SecureGPT, enforces NIST CSF controls, and automatically raises actionable Jira tickets** for high‑severity threats.  
The pipeline is built around four AWS Lambda agents—**Ingestor, Analyzer, Aggregator, and Ticket Generator**—and uses synthetic plus live‑captured data to ensure repeatable, privacy‑safe testing.

---

## 📂 Repository Structure
```text
.
├── data/                     # ➜ All datasets
│   ├── network_traffic/      #   – Synthetic & PCAP/CSV packet captures
│   ├── anomaly_logs/         #   – Cyber Sentinel anomaly logs
│   └── nist/                 #   – NIST SP 800‑53 r5 (PDF + JSON subsets)
│
├── agents/                   # ➜ Source for the four Lambda agents
│   ├── ingestor/             #   – NetGuard Ingestor (Agent 1)
│   ├── analyzer/             #   – NetGuard Analyzer (Agent 2)
│   ├── aggregator/           #   – NetGuard Aggregator (Agent 3)
│   └── ticket_generator/     #   – NetGuard Ticket Generator (Agent 4)
│
├── prompts/                  # ➜ SecureGPT prompt templates
│   ├── ingestor_prompt.txt
│   ├── analyzer_prompt.txt
│   ├── aggregator_prompt.txt
│   └── ticket_generator_prompt.txt
│
├── diagrams/                 # ➜ PNG / Mermaid / Visio exports
│   ├── high_level_architecture.png
│   ├── data_flow_architecture.png
│   └── agents_sequence.mmd
│
├── results/                  # ➜ Metrics, ROC curves, dashboards
│   ├── test_reports/
│   └── notebooks/
│
└── README.md                 # ➜ You’re here
