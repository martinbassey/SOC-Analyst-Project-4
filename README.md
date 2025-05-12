# SOC-Analyst-Project-4
SOC Analyst Project 4: Personal Phishing Analysis Playbook

**By:** Martin Bassey  
**Date:** 2025/05/12  
**Version:** 1.0

---

## Executive Summary

This playbook was drafted based on my hands-on learning and lab training in phishing analysis lessons, and in line withe real-world setting in SOC field, it provides a structured, step-by-step guide for triaging, investigating, and responding to phishing emails in a SOC environment. It is designed to ensure thorough, consistent, and efficient handling of phishing threats, from initial detection to remediation and user education.

---

## Table of Contents

- [1. Preparation & Prerequisites](#1-preparation--prerequisites)
- [2. Header Analysis](#2-header-analysis)
- [3. URL/Link Analysis](#3-urllink-analysis)
- [4. Attachment Analysis](#4-attachment-analysis)
- [5. User Reporting & Intake](#5-user-reporting--intake)
- [6. Mitigation & Response](#6-mitigation--response)
- [7. Post-Incident Review](#7-post-incident-review)
- [8. IOC Template](#9-ioc-template)
- [9. References](#10-references)
- [10. Author's Note](#10-Author's-Note)

---

## 1. Preparation & Prerequisites

- Ensure email logging and mailbox auditing are enabled.
- Confirm access to necessary tools (sandbox, threat intelligence, email gateway).
- Assign roles for investigation, response, and user communication.

---

## 2. Header Analysis

**Objective:** How to identify sender spoofing, forged headers, and suspicious routing.

**Process Involved:**  
- Extract full email headers from the reported message.
- Analyze:
  - `From`, `Reply-To`, `Return-Path`
  - `Received` chain (trace source IPs)
  - SPF, DKIM, DMARC results
- Look for mismatches, anomalies, or unusual sending infrastructure.

**Tools Used:**  
- Email client "Show Original" or "View Headers"
- Sublime Text  
- eioc.py (Email IOC Extractor Python script)

**Commands Used:** 
  | Tool         | Example Command                          | Purpose                        |
|--------------|----------------------------------------|-------------------------------|
| Sublime Text | `subl suspicious_email.eml`             | Open file in Sublime Text |
| eioc.py      | `python3 eioc.py suspicious_email.eml`  | Extract IOCs from email in terminal |


### Summary of Header Analysis

I used the `eioc.py` script and Sublime Text with Ubuntu Terminal environment to extract and analyze email headers and IOCs from the `.eml` files provided. This approach allowed me to manually review key header fields such as `From`, `Reply-To`, `Received`, and authentication results (SPF, DKIM, DMARC), without relying on online header analysis tools.

---

## 3. URL/Link Analysis

**Objective:** How to detect malicious or suspicious links and identify phishing infrastructure.

**Process Involved:**  
- Hover over URLs/links; compare display text vs. actual URL.
- Extract and analyze all URLs.
- Check for:
  - Obfuscation (URL shorteners, hex encoding)
  - Typosquatting or lookalike domains
  - Redirections to suspicious sites

**Tools:**  
- [URLscan.io](https://urlscan.io/), [VirusTotal](https://www.virustotal.com/), WHOIS lookup

---

## 4. Attachment Analysis

**Objective:** How to identify and analyze potentially malicious attachments.

**Process Involved:**  
- **Never open attachments on production endpoints.**
- Extract and scan attachments using static analysis tools.
- Analyze for:
  - Macros, embedded scripts, or executables
  - Known malware signatures
  - Unusual file properties or obfuscation

**Tools:**  
- [Hybrid Analysis](https://www.hybrid-analysis.com/) and VirusTotal
- eioc.py to extract IOCs from email in terminal
- Oledump.py (for Office macros/imbedded files), PDFid, pdf-parser (for PDFs)

**Example Command:**  

## Example Commands for Malware and Phishing Analysis Tools (Ubuntu Terminal)

| Tool                    | Example Command                                                                                   | Purpose                                              |
|-------------------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------|
| **Hybrid Analysis**     | *Upload via web interface:* [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/) | Submit suspicious files for automated sandbox analysis|
| **VirusTotal**          | *Upload hash value/IP via web interface:* [https://www.virustotal.com/](https://www.virustotal.com/gui/home/upload)  | Submit file for multi-engine scanning and reputation check |
| **eioc.py**             | `python3 ../../eioc.py suspicious_email.eml`                                                           | Extract IOCs (URLs, hashes, IPs) from email in terminal |
| **Oledump.py**          | `python3 ../../oledump.py suspicious_attachment.docm`                                        | Analyze Office files for macros and embedded objects  |
| **PDFid.py**            | `python3 ../../pdfid.py suspicious_file.pdf`                                                          | Static analysis of PDF structure and suspicious elements |
| **pdf-parser.py**       | `python3 ../../pdf-parser.py suspicious_file.pdf`                                                  | Deep dive into PDF objects, streams, and actions      |

> **Note:**  
> - For Hybrid Analysis, files are uploaded via the web interface at [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/).  

---

## 5. User Reporting & Intake

**Objective:** How to ensure accurate intake and documentation of user-reported phishing.

**Process Invloved:**  
- Instruct users to report suspicious emails via the official mechanism (Outlook "Report Phish" button, helpdesk ticket).
- Collect and log:
  - Full email with headers and attachments
  - User's description of the incident
  - Any actions taken (clicked links, opened attachments)

**Tools:**  
- General phishing reporting template in GitHub Markdown documentation format.

---

## 6. Mitigation & Response

**Objective:** Contain, eradicate, and recover from phishing incidents.

**Process:**  
- Quarantine or delete phishing emails from all affected mailboxes.
- Block malicious domains, URLs, and sender addresses at the gateway.
- Reset credentials for affected users.
- Scan endpoints for malware or persistence mechanisms.
- Notify and educate users as needed.
- Document the incident and update detection rules.

**Tools:**  
- Email security gateway (Microsoft Defender)
- Endpoint detection & response (EDR)

---

## 7. Post-Incident Review

- Review what detection and response steps worked and what could be improved.
- Update playbook and detection rules based on lessons learned.
- Share anonymized findings with the team for training and awareness.

---

## 8. IOC Template

| Type        | Value              | Source/Context        | First Seen   | Notes                |
|-------------|--------------------|----------------------|--------------|----------------------|
| File Hash   | SHA256           | Attachment           | Input Date Identified       | Malware family     |
| URL (in defanged format)         | https[.]://maliciousweblin[.]com         | Email body/link      |   Input Date Identified    | Phishing page      |
| Domain Name | malicious.com    | Redirect/landing     | Input Date Identified       | Registrar info     |
| IP Address  | 127.0.0.1          | Email header/link    | Input Date Identified      | Geo, ASN           |
| Email Addr  | attacker@maliciousweblink.com     | From/Reply-To        | Input Date Identified      | Spoofed?           |

---

## 9. References

- Counteractive Phishing Playbook
- Exabeam Phishing Playbook Template
- Splunk Playbook Series: Phishing
- Microsoft Phishing Investigation Playbook
- MISP Playbooks

---
## 10.  Author's Note

This playbook is a culmination of my ongoing journey in developing practical skills as a SOC Analyst. It reflects hands-on learning, research, and application of industry best practices in phishing analysis and incident response. I am passionate about growing my expertise in cybersecurity and am eager to connect with experienced professionals in the field.

If you are a mentor or cybersecurity expert willing to guide and share knowledge, I would greatly appreciate the opportunity to learn from you. Please feel free to reach out or connect!

Together, we can build stronger defenses against evolving cyber threats.

## THANK YOU!
