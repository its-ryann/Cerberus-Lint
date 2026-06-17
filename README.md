# 🐺 Cerberus-Lint

`Cerberus-Lint` is a lightweight, production-ready security triage utility designed for DevSecOps pipelines and automated incident response workflows. Inspired by the mythic three-headed guardian of gates, this tool acts as an automated gatekeeper for infrastructure telemetry, scanning raw server logs line-by-line to intercept and expose brute-force authentication attacks before they manifest into breaches.

Unlike traditional heavy log-parsing frameworks, `Cerberus-Lint` focuses entirely on defensive speed, low memory overhead, and secure-by-design input sanitization.

### 🛡️ Core Capabilities

* **Streamed Log Processing:** Utilizes memory-efficient line-by-line file streaming (Python generators) to parse massive multi-gigabyte log datasets securely without causing container Out-Of-Memory (OOM) crashes.
* **Threat Triage Engine:** Implements precise regular expressions to extract and aggregate critical security telemetry: Source IPs, Target Usernames, and Attack Timestamps.
* **Structured DevSecOps Output:** Sanitizes raw, unstructured log entries and outputs deterministic, machine-readable JSON payloads perfectly suited for direct ingestion by SIEM tools, firewalls (such as Cloudflare or iptables), or automated slack alerting webhooks.
* **Defensive Error Handling:** Built with robust, defensive exception handling to prevent runtime crashes, ensuring high reliability when embedded into continuous integration or automated infrastructure pipelines.
