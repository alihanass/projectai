import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")

SEED_NODES = [
    {"id": "internet",   "label": "Internet",      "kuLabel": "ئەنتەرنێت",           "role": "Attacker",    "kuRole": "هێرشبەر",        "tag": "START", "x": 80,  "y": 215, "h": 8},
    {"id": "firewall",   "label": "Edge Firewall", "kuLabel": "فایەروۆڵی سنوور",     "role": "Perimeter",   "kuRole": "پەراوێز",        "tag": "FW",    "x": 245, "y": 65,  "h": 6},
    {"id": "web_srv",    "label": "Web Server",    "kuLabel": "وێب سێرڤەر",          "role": "DMZ",         "kuRole": "ناوچەی DMZ",     "tag": "DMZ",   "x": 245, "y": 168, "h": 5},
    {"id": "vpn_gw",     "label": "VPN Gateway",   "kuLabel": "دەروازەی VPN",        "role": "Remote",      "kuRole": "پەیوەندیی دوور", "tag": "VPN",   "x": 245, "y": 272, "h": 4},
    {"id": "emp_pc",     "label": "Employee PC",   "kuLabel": "کۆمپیوتەری فەرمانبەر", "role": "Workstation", "kuRole": "وێستگەی کار",    "tag": "PC",    "x": 245, "y": 368, "h": 5},
    {"id": "app_srv",    "label": "App Server",    "kuLabel": "ئەپ سێرڤەر",          "role": "Internal",    "kuRole": "ناوخۆیی",        "tag": "APP",   "x": 470, "y": 105, "h": 3},
    {"id": "mail_srv",   "label": "Mail Server",   "kuLabel": "ئیمەیڵ سێرڤەر",       "role": "Internal",    "kuRole": "ناوخۆیی",        "tag": "MAIL",  "x": 470, "y": 228, "h": 4},
    {"id": "ad_srv",     "label": "Active Dir",    "kuLabel": "ئەکتیڤ دایرێکتۆری",   "role": "Identity",    "kuRole": "ناسنامە (IAM)",  "tag": "AD",    "x": 470, "y": 348, "h": 2},
    {"id": "backup_srv", "label": "Backup Server", "kuLabel": "سێرڤەری باکئەپ",      "role": "Storage",     "kuRole": "هەڵگرتن",        "tag": "BKUP",  "x": 665, "y": 88,  "h": 2},
    {"id": "core_db",    "label": "Core Database", "kuLabel": "داتابەیسی سەرەکی",    "role": "Crown Jewel", "kuRole": "سامانی سەرەکی",  "tag": "GOAL",  "x": 790, "y": 245, "h": 0},
]

SEED_EDGES = [
    {
        "id": "e1", "from": "internet", "to": "firewall", "cost": 4, "vuln": "Port Bypass",
        "curveX": None, "t": None,
        "cvss": 7.5, "severity": "High", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
        "cia": {"c": "Medium", "i": "High", "a": "Low"},
        "technique": {
            "en": "Firewall Port / Rule Bypass via Exposed Management Service",
            "ku": "تێپەڕاندنی یاساکانی فایەروۆڵ لە ڕێگەی پۆرتی بەڕێوەبردنی کراوەوە",
        },
        "policy": {
            "en": "Default-Deny Perimeter Firewall & Change Control Policy",
            "ku": "سیاسەتی ڕەتکردنەوەی بنەڕەتی (Default-Deny) و کۆنترۆڵی گۆڕانکاری",
        },
        "mechanism": {
            "en": "Next-Gen Firewall (NGFW) Rule Hardening, Port Closure & Intrusion Prevention System (IPS)",
            "ku": "توندکردنەوەی یاساکانی NGFW، داخستنی پۆرتە ناپێویستەکان و سیستەمی ڕێگری لە دزەکردن (IPS)",
        },
    },
    {
        "id": "e2", "from": "internet", "to": "web_srv", "cost": 5, "vuln": "SQL Injection",
        "curveX": None, "t": None,
        "cvss": 9.8, "severity": "Critical", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "High"},
        "technique": {
            "en": "SQL Injection on Public Web Endpoint (OWASP A03 / MITRE T1190)",
            "ku": "هێرشی SQL Injection لەسەر خاڵی کۆتایی وێب (OWASP A03 / MITRE T1190)",
        },
        "policy": {
            "en": "Secure Coding Standards & Mandatory Input Validation Policy",
            "ku": "سیاسەتی کۆدکردنی سەلامەت و پشکنینی ناچاریی زانیارییە داخڵکراوەکان",
        },
        "mechanism": {
            "en": "Parameterized Queries (Prepared Statements), Strict Input Sanitization & Web Application Firewall (WAF)",
            "ku": "بەکارهێنانی Parameterized Queries، پاککردنەوەی وردی Input و فایەروۆڵی ئەپلیکەیشنی وێب (WAF)",
        },
    },
    {
        "id": "e3", "from": "internet", "to": "vpn_gw", "cost": 6, "vuln": "Cred Stuffing",
        "curveX": None, "t": None,
        "cvss": 7.4, "severity": "High", "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cia": {"c": "High", "i": "Medium", "a": "Low"},
        "technique": {
            "en": "Credential Stuffing & Automated Password Spraying (MITRE T1110.004)",
            "ku": "تاقیکردنەوەی وشەی نهێنی دزراو و هێرشی Password Spraying (MITRE T1110.004)",
        },
        "policy": {
            "en": "Zero-Trust Remote Access & Strong Authentication Policy",
            "ku": "سیاسەتی دەستڕاگەیشتنی دووری Zero-Trust و پشتڕاستکردنەوەی بەهێز",
        },
        "mechanism": {
            "en": "Multi-Factor Authentication (MFA), Adaptive Rate Limiting & Account Lockout Protection",
            "ku": "پشتڕاستکردنەوەی دوو-هۆکاری (MFA)، سنووردارکردنی هەوڵەکانی چوونەژوورەوە و داخستنی هەژمار",
        },
    },
    {
        "id": "e4", "from": "internet", "to": "emp_pc", "cost": 2, "vuln": "Phishing",
        "curveX": None, "t": None,
        "cvss": 8.1, "severity": "High", "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L",
        "cia": {"c": "High", "i": "High", "a": "Medium"},
        "technique": {
            "en": "Spear-Phishing Malicious Attachment / Credential Harvest (MITRE T1566)",
            "ku": "ئیمەیڵی ساختەی فیشینگ و فایلی زیانبەخش بۆ دزینی دەستڕاگەیشتن (MITRE T1566)",
        },
        "policy": {
            "en": "Security Awareness Training & Email Security Governance Policy",
            "ku": "سیاسەتی ڕاهێنانی هۆشیاریی ئاسایش و حوکمڕانیی پاراستنی ئیمەیڵ",
        },
        "mechanism": {
            "en": "DMARC/DKIM/SPF Email Filtering, Secure Email Gateway & Endpoint Detection and Response (EDR)",
            "ku": "فلتەری DMARC/DKIM/SPF، دەروازەی پاراستنی ئیمەیڵ و سیستەمی EDR لەسەر کۆمپیوتەرەکان",
        },
    },
    {
        "id": "e5", "from": "firewall", "to": "app_srv", "cost": 4, "vuln": "ACL Flaw",
        "curveX": None, "t": None,
        "cvss": 6.8, "severity": "Medium", "vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:M/I:H/A:L",
        "cia": {"c": "Medium", "i": "High", "a": "Low"},
        "technique": {
            "en": "Overly Permissive Network ACL Rule Exploitation",
            "ku": "قۆستنەوەی کەموکوڕی و ڕێگەپێدانی زیادەی لیستی کۆنترۆڵی دەستڕاگەیشتن (ACL)",
        },
        "policy": {
            "en": "Least Privilege Networking & Micro-Segmentation Policy",
            "ku": "سیاسەتی کەمترین دەسەڵات (Least Privilege) و دابەشکردنی وردی نێتۆرک",
        },
        "mechanism": {
            "en": "Automated Firewall ACL Audits, VLAN/Zone Segmentation & Zero-Trust Network Access (ZTNA)",
            "ku": "وردبینیی خۆکاری یاساکانی ACL، جیاکردنەوەی ناوچەکانی نێتۆرک (VLAN) و سیستەمی ZTNA",
        },
    },
    {
        "id": "e6", "from": "firewall", "to": "vpn_gw", "cost": 3, "vuln": "Weak TLS",
        "curveX": 332, "t": 0.28,
        "cvss": 5.9, "severity": "Medium", "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cia": {"c": "High", "i": "Medium", "a": "Low"},
        "technique": {
            "en": "Weak TLS Cipher Negotiation & Protocol Downgrade (MITM)",
            "ku": "دابەزاندنی پرۆتۆکۆڵی TLS و قۆستنەوەی کۆدکردنی لاواز (هێرشی MITM)",
        },
        "policy": {
            "en": "Enterprise Cryptographic Standards & Data-in-Transit Policy",
            "ku": "سیاسەتی ستانداردەکانی کۆدکردن و پاراستنی داتا لە کاتی گواستنەوەدا",
        },
        "mechanism": {
            "en": "Enforce TLS 1.3 Only, Disable Legacy Ciphers (TLS 1.0/1.1) & Mutual TLS Authentication",
            "ku": "ناچارکردنی TLS 1.3، ناچالاککردنی کۆدە کۆنەکان (TLS 1.0/1.1) و پشتڕاستکردنەوەی mTLS",
        },
    },
    {
        "id": "e7", "from": "web_srv", "to": "app_srv", "cost": 3, "vuln": "RCE Exploit",
        "curveX": None, "t": None,
        "cvss": 9.8, "severity": "Critical", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "High"},
        "technique": {
            "en": "Remote Code Execution via Insecure Deserialization / Command Injection (MITRE T1190)",
            "ku": "جێبەجێکردنی کۆد لە دوورەوە (RCE) لە ڕێگەی کەلێنی ئەپلیکەیشنەوە (MITRE T1190)",
        },
        "policy": {
            "en": "Rapid Vulnerability Remediation & Patch Management Policy",
            "ku": "سیاسەتی خێرای چارەسەرکردنی کەلێنەکان و بەڕێوەبردنی نوێکردنەوە (Patch Management)",
        },
        "mechanism": {
            "en": "Emergency Security Patching, Container/Runtime Sandboxing, WAF & Least-Privilege Service Accounts",
            "ku": "نوێکردنەوەی خێرای ئاسایش، جیاکردنەوەی Sandbox، فایەروۆڵی WAF و کەمکردنەوەی دەسەڵاتی سێرڤیس",
        },
    },
    {
        "id": "e8", "from": "web_srv", "to": "mail_srv", "cost": 2, "vuln": "SSRF",
        "curveX": None, "t": None,
        "cvss": 7.2, "severity": "High", "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
        "cia": {"c": "High", "i": "Medium", "a": "Low"},
        "technique": {
            "en": "Server-Side Request Forgery Pivoting to Internal Mail Relay (OWASP A10)",
            "ku": "ساختەکردنی داواکاریی سێرڤەر (SSRF) بۆ گەیشتن بە سێرڤەری ناوخۆیی ئیمەیڵ (OWASP A10)",
        },
        "policy": {
            "en": "DMZ-to-Internal Isolation & Zero-Trust Egress Policy",
            "ku": "سیاسەتی جیاکردنەوەی DMZ لە نێتۆرکی ناوخۆیی و کۆنترۆڵی دەرچوون (Egress)",
        },
        "mechanism": {
            "en": "Strict URL/Host Allowlisting, Egress Firewall Filtering & Authenticated Internal APIs",
            "ku": "بەکارهێنانی لیستی ڕێگەپێدراو (Allowlist)، فلتەری Egress و پشتڕاستکردنەوە بۆ API ناوخۆییەکان",
        },
    },
    {
        "id": "e9", "from": "vpn_gw", "to": "ad_srv", "cost": 4, "vuln": "Kerberoast",
        "curveX": None, "t": 0.34,
        "cvss": 8.4, "severity": "High", "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        "cia": {"c": "High", "i": "High", "a": "Low"},
        "technique": {
            "en": "Kerberoasting — Active Directory Service Ticket Offline Cracking (MITRE T1558.003)",
            "ku": "هێرشی Kerberoasting بۆ شکاندنی تیکێتی خزمەتگوزارییەکانی Active Directory (MITRE T1558.003)",
        },
        "policy": {
            "en": "Privileged Identity & Service Account Password Hardening Policy",
            "ku": "سیاسەتی بەڕێوەبردنی ناسنامەی باڵا و بەهێزکردنی وشەی نهێنیی هەژماری خزمەتگوزاری",
        },
        "mechanism": {
            "en": "Group Managed Service Accounts (gMSA), AES-256 Kerberos Enforcement & SIEM Anomaly Alerts",
            "ku": "بەکارهێنانی هەژماری gMSA، ناچارکردنی کۆدکردنی AES-256 لە Kerberos و چاودێریی SIEM",
        },
    },
    {
        "id": "e10", "from": "emp_pc", "to": "mail_srv", "cost": 2, "vuln": "Session Hijack",
        "curveX": None, "t": 0.66,
        "cvss": 6.5, "severity": "Medium", "vector": "AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N",
        "cia": {"c": "High", "i": "Medium", "a": "Low"},
        "technique": {
            "en": "Webmail Session Cookie Theft & Replay Hijacking (MITRE T1539)",
            "ku": "دزینی کووکی و تۆکنی دانیشتنی ئیمەیڵ و داگیرکردنی سێشن (MITRE T1539)",
        },
        "policy": {
            "en": "Secure Session Lifecycle & Endpoint Browser Hygiene Policy",
            "ku": "سیاسەتی بەڕێوەبردنی سەلامەتی ماوەی سێشن و پاراستنی وێبگەڕی بەکارهێنەر",
        },
        "mechanism": {
            "en": "HttpOnly/Secure/SameSite Cookies, Short Session Timeouts & Continuous Device-Bound Tokens",
            "ku": "چالاککردنی HttpOnly/Secure/SameSite، کەمکردنەوەی کاتی سێشن و بەستنەوەی تۆکن بە ئامێرەوە",
        },
    },
    {
        "id": "e11", "from": "emp_pc", "to": "ad_srv", "cost": 3, "vuln": "Pass-the-Hash",
        "curveX": None, "t": None,
        "cvss": 8.8, "severity": "High", "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "Medium"},
        "technique": {
            "en": "Pass-the-Hash Lateral Movement Using Extracted NTLM Hashes (MITRE T1550.002)",
            "ku": "هێرشی Pass-the-Hash بۆ جووڵەی تەنیشتەکی بە بەکارهێنانی هاشی NTLM (MITRE T1550.002)",
        },
        "policy": {
            "en": "Credential Hygiene & Active Directory Tiered Administration Policy",
            "ku": "سیاسەتی پاکڕاگرتنی زانیاریی چوونەژوورەوە و پلەبەندیی بەڕێوەبردنی Active Directory",
        },
        "mechanism": {
            "en": "Windows Defender Credential Guard, Disable NTLM, LAPS & EDR Lateral-Movement Blocking",
            "ku": "چالاککردنی Credential Guard، ناچالاککردنی NTLM، سیستەمی LAPS و بلۆککردنی جووڵەی ناوخۆیی بە EDR",
        },
    },
    {
        "id": "e12", "from": "mail_srv", "to": "ad_srv", "cost": 3, "vuln": "Token Theft",
        "curveX": None, "t": None,
        "cvss": 7.8, "severity": "High", "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        "cia": {"c": "High", "i": "High", "a": "Low"},
        "technique": {
            "en": "OAuth / Identity Access Token Theft & Impersonation (MITRE T1528)",
            "ku": "دزینی تۆکنی دەستڕاگەیشتنی OAuth و خۆنواندن لە جێگەی بەکارهێنەر (MITRE T1528)",
        },
        "policy": {
            "en": "Zero-Trust Identity & Short-Lived Token Governance Policy",
            "ku": "سیاسەتی ناسنامەی Zero-Trust و کۆنترۆڵکردنی تۆکنە کورتخایەنەکان",
        },
        "mechanism": {
            "en": "Conditional Access Policies, Phishing-Resistant FIDO2 MFA & Automated Token Revocation",
            "ku": "یاساکانی Conditional Access، سیستەمی MFAـی دژە-فیشینگ (FIDO2) و هەڵوەشاندنەوەی خۆکاری تۆکن",
        },
    },
    {
        "id": "e13", "from": "app_srv", "to": "backup_srv", "cost": 2, "vuln": "Open Share",
        "curveX": None, "t": None,
        "cvss": 5.3, "severity": "Medium", "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L",
        "cia": {"c": "Medium", "i": "Low", "a": "Medium"},
        "technique": {
            "en": "Unrestricted Internal SMB/NFS Backup Share Enumeration (MITRE T1039)",
            "ku": "دەستڕاگەیشتن بە فۆڵدەری هاوبەشی کراوەی SMB/NFS لەسەر سێرڤەری باکئەپ (MITRE T1039)",
        },
        "policy": {
            "en": "Data Classification & Storage Least-Privilege Access Policy",
            "ku": "سیاسەتی پۆلێنکردنی داتا و کەمترین دەسەڵات بۆ یەکەکانی هەڵگرتن",
        },
        "mechanism": {
            "en": "Role-Based Access Control (RBAC), SMB Signing/Encryption & Backup Network Segmentation",
            "ku": "کۆنترۆڵی دەستڕاگەیشتن بەپێی ڕۆڵ (RBAC)، کۆدکردنی SMB و جیاکردنەوەی نێتۆرکی باکئەپ",
        },
    },
    {
        "id": "e14", "from": "app_srv", "to": "core_db", "cost": 5, "vuln": "DB PrivEsc",
        "curveX": None, "t": 0.42,
        "cvss": 9.1, "severity": "Critical", "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "High"},
        "technique": {
            "en": "Database Privilege Escalation via Over-Privileged App DBA Role",
            "ku": "بەرزکردنەوەی دەسەڵات لە داتابەیسدا لە ڕێگەی هەژماری خزمەتگوزاریی خاوەن دەسەڵاتی زیادە",
        },
        "policy": {
            "en": "Database Least Privilege & Separation of Duties Policy",
            "ku": "سیاسەتی کەمترین دەسەڵاتی داتابەیس و جیاکردنەوەی ئەرکەکان (Separation of Duties)",
        },
        "mechanism": {
            "en": "Strict DB Role Scoping, Database Activity Monitoring (DAM) & Stored-Procedure Hardening",
            "ku": "سنووردارکردنی وردی ڕۆڵەکانی داتابەیس، سیستەمی چاودێریی داتابەیس (DAM) و توندکردنەوەی ڕێگەپێدان",
        },
    },
    {
        "id": "e15", "from": "ad_srv", "to": "backup_srv", "cost": 2, "vuln": "Admin Creds",
        "curveX": None, "t": None,
        "cvss": 8.6, "severity": "High", "vector": "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "High"},
        "technique": {
            "en": "Shared Domain Admin Credential Reuse Against Backup Infrastructure (MITRE T1078)",
            "ku": "بەکارهێنانەوەی زانیاریی ئەدمینی دۆمەین بۆ داگیرکردنی سێرڤەری باکئەپ (MITRE T1078)",
        },
        "policy": {
            "en": "Immutable Backup & Domain-Isolated Administration Policy",
            "ku": "سیاسەتی باکئەپی نەگۆڕ (Immutable) و جیاکردنەوەی بەڕێوەبردن لە دۆمەین",
        },
        "mechanism": {
            "en": "Dedicated Non-Domain Credentials, Air-Gapped Immutable Snapshots & PAM Vaulting",
            "ku": "هەژماری سەربەخۆ لە دەرەوەی دۆمەین، باکئەپی نەگۆڕی دابڕاو و سیستەمی PAM Vault",
        },
    },
    {
        "id": "e16", "from": "ad_srv", "to": "core_db", "cost": 3, "vuln": "Domain Admin",
        "curveX": None, "t": None,
        "cvss": 9.6, "severity": "Critical", "vector": "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "cia": {"c": "High", "i": "High", "a": "High"},
        "technique": {
            "en": "Domain Admin Takeover Leading to Full Crown-Jewel Database Compromise",
            "ku": "بەکارهێنانی دەسەڵاتی Domain Admin بۆ کۆنترۆڵکردنی تەواوەتیی داتابەیسی سەرەکی",
        },
        "policy": {
            "en": "Zero-Trust Crown-Jewel Protection & Just-in-Time (JIT) Privileged Access Policy",
            "ku": "سیاسەتی پاراستنی Zero-Trust بۆ سامانی سەرەکی و دەستڕاگەیشتنی کاتی (Just-in-Time)",
        },
        "mechanism": {
            "en": "Privileged Access Management (PAM), Mandatory MFA on DB Admin Login & Micro-Segmentation",
            "ku": "بەڕێوەبردنی دەستڕاگەیشتنی باڵا (PAM)، ناچارکردنی MFA بۆ ئەدمینی داتابەیس و جیاکردنەوەی نێتۆرک",
        },
    },
    {
        "id": "e17", "from": "backup_srv", "to": "core_db", "cost": 4, "vuln": "Key Dump",
        "curveX": None, "t": None,
        "cvss": 9.0, "severity": "Critical", "vector": "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:M",
        "cia": {"c": "High", "i": "High", "a": "Medium"},
        "technique": {
            "en": "Database Encryption Key & Credential Extraction from Backup Snapshots (MITRE T1552)",
            "ku": "دەرهێنانی کلیلی کۆدکردن و زانیارییە نهێنییەکانی داتابەیس لە فایلەکانی باکئەپ (MITRE T1552)",
        },
        "policy": {
            "en": "Cryptographic Key Separation & Lifecycle Management Policy",
            "ku": "سیاسەتی جیاکردنەوەی کلیلی کۆدکردن و بەڕێوەبردنی سوڕی ژیانی کلیلەکان",
        },
        "mechanism": {
            "en": "Hardware Security Module (HSM) / KMS Key Isolation, Envelope Encryption & Audit Logging",
            "ku": "جیاکردنەوەی کلیلەکان لە ناو HSM / KMS، کۆدکردنی بەرگدار و تۆمارکردنی هەموو دەستڕاگەیشتنەکان",
        },
    },
]

SEED_SCENARIOS = [
    {
        "name": "Baseline Enterprise Exposure",
        "description": "Default unpatched enterprise network with all 17 vulnerability vectors active.",
        "start_node": "internet",
        "goal_node": "core_db",
        "algo": "ASTAR",
        "dls_limit": 2,
        "patched_edges": [],
        "risk_score": 9.3,
        "risk_severity": "Critical",
    },
    {
        "name": "IAM Hardening (Block AD Pivot)",
        "description": "Mitigates Domain Admin (e16) & Pass-the-Hash (e11) via PAM + Credential Guard.",
        "start_node": "internet",
        "goal_node": "core_db",
        "algo": "ASTAR",
        "dls_limit": 2,
        "patched_edges": ["e11", "e16"],
        "risk_score": 8.9,
        "risk_severity": "High",
    },
    {
        "name": "Crown-Jewel Zero-Trust Isolation",
        "description": "Patches all direct Core Database vectors (e14, e16, e17) achieving full protection.",
        "start_node": "internet",
        "goal_node": "core_db",
        "algo": "ASTAR",
        "dls_limit": 2,
        "patched_edges": ["e14", "e16", "e17"],
        "risk_score": 0.0,
        "risk_severity": "Secured",
    },
]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@contextmanager
def get_connection(db_path=None):
    target_path = DB_PATH if db_path is None else db_path
    conn = sqlite3.connect(target_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 15000;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=None):
    with get_connection(db_path) as conn:
        # Use standard DELETE journal mode for full compatibility on networked filesystems (e.g., PythonAnywhere NFS)
        try:
            conn.execute("PRAGMA journal_mode = DELETE;")
        except sqlite3.OperationalError:
            pass
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                ku_label TEXT NOT NULL,
                role TEXT NOT NULL,
                ku_role TEXT NOT NULL,
                tag TEXT NOT NULL,
                x INTEGER NOT NULL,
                y INTEGER NOT NULL,
                h INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                from_node TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                to_node TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                cost INTEGER NOT NULL CHECK (cost BETWEEN 1 AND 20),
                vuln TEXT NOT NULL,
                curve_x REAL,
                t_pos REAL,
                cvss REAL NOT NULL CHECK (cvss >= 0.0 AND cvss <= 10.0),
                severity TEXT NOT NULL,
                vector TEXT NOT NULL,
                cia_c TEXT NOT NULL,
                cia_i TEXT NOT NULL,
                cia_a TEXT NOT NULL,
                technique_en TEXT NOT NULL,
                technique_ku TEXT NOT NULL,
                policy_en TEXT NOT NULL,
                policy_ku TEXT NOT NULL,
                mechanism_en TEXT NOT NULL,
                mechanism_ku TEXT NOT NULL,
                is_patched INTEGER NOT NULL DEFAULT 0,
                patched_at TEXT
            );

            CREATE TABLE IF NOT EXISTS mitigation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                edge_id TEXT REFERENCES edges(id) ON DELETE SET NULL,
                vuln TEXT NOT NULL,
                action TEXT NOT NULL,
                note TEXT,
                risk_before REAL,
                risk_after REAL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS search_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algo TEXT NOT NULL,
                start_node TEXT NOT NULL,
                goal_node TEXT NOT NULL,
                dls_limit INTEGER NOT NULL,
                found INTEGER NOT NULL,
                status_key TEXT NOT NULL,
                status_arg INTEGER,
                path_json TEXT NOT NULL,
                cost INTEGER,
                hops INTEGER,
                risk_score REAL NOT NULL,
                risk_severity TEXT NOT NULL,
                cia_c TEXT NOT NULL,
                cia_i TEXT NOT NULL,
                cia_a TEXT NOT NULL,
                expanded INTEGER NOT NULL,
                max_frontier INTEGER NOT NULL,
                patched_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scenarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                start_node TEXT NOT NULL,
                goal_node TEXT NOT NULL,
                algo TEXT NOT NULL,
                dls_limit INTEGER NOT NULL DEFAULT 2,
                patched_edges_json TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_severity TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
            CREATE INDEX IF NOT EXISTS idx_edges_patched ON edges(is_patched);
            CREATE INDEX IF NOT EXISTS idx_logs_created ON mitigation_logs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_runs_created ON search_runs(created_at DESC);
            """
        )

        # Seed nodes if empty
        node_count = conn.execute("SELECT COUNT(*) AS c FROM nodes").fetchone()["c"]
        if node_count == 0:
            conn.executemany(
                """
                INSERT INTO nodes (id, label, ku_label, role, ku_role, tag, x, y, h)
                VALUES (:id, :label, :kuLabel, :role, :kuRole, :tag, :x, :y, :h)
                """,
                SEED_NODES,
            )

        # Seed edges if empty
        edge_count = conn.execute("SELECT COUNT(*) AS c FROM edges").fetchone()["c"]
        if edge_count == 0:
            conn.executemany(
                """
                INSERT INTO edges (
                    id, from_node, to_node, cost, vuln, curve_x, t_pos,
                    cvss, severity, vector, cia_c, cia_i, cia_a,
                    technique_en, technique_ku, policy_en, policy_ku,
                    mechanism_en, mechanism_ku, is_patched, patched_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, 0, NULL
                )
                """,
                [
                    (
                        e["id"], e["from"], e["to"], e["cost"], e["vuln"], e["curveX"], e["t"],
                        e["cvss"], e["severity"], e["vector"], e["cia"]["c"], e["cia"]["i"], e["cia"]["a"],
                        e["technique"]["en"], e["technique"]["ku"], e["policy"]["en"], e["policy"]["ku"],
                        e["mechanism"]["en"], e["mechanism"]["ku"],
                    )
                    for e in SEED_EDGES
                ],
            )

        # Seed starter defense scenarios if empty
        scenario_count = conn.execute("SELECT COUNT(*) AS c FROM scenarios").fetchone()["c"]
        if scenario_count == 0:
            now = utc_now()
            conn.executemany(
                """
                INSERT INTO scenarios (
                    name, description, start_node, goal_node, algo, dls_limit,
                    patched_edges_json, risk_score, risk_severity, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        s["name"], s["description"], s["start_node"], s["goal_node"],
                        s["algo"], s["dls_limit"], json.dumps(s["patched_edges"]),
                        s["risk_score"], s["risk_severity"], now,
                    )
                    for s in SEED_SCENARIOS
                ],
            )

        conn.commit()


def row_to_node(row):
    return {
        "id": row["id"],
        "label": row["label"],
        "kuLabel": row["ku_label"],
        "role": row["role"],
        "kuRole": row["ku_role"],
        "tag": row["tag"],
        "x": row["x"],
        "y": row["y"],
        "h": row["h"],
    }


def row_to_edge(row):
    edge = {
        "id": row["id"],
        "from": row["from_node"],
        "to": row["to_node"],
        "cost": row["cost"],
        "vuln": row["vuln"],
        "cvss": float(row["cvss"]),
        "severity": row["severity"],
        "vector": row["vector"],
        "cia": {
            "c": row["cia_c"],
            "i": row["cia_i"],
            "a": row["cia_a"],
        },
        "technique": {"en": row["technique_en"], "ku": row["technique_ku"]},
        "policy": {"en": row["policy_en"], "ku": row["policy_ku"]},
        "mechanism": {"en": row["mechanism_en"], "ku": row["mechanism_ku"]},
        "isPatched": bool(row["is_patched"]),
        "patchedAt": row["patched_at"],
    }
    if row["curve_x"] is not None:
        edge["curveX"] = float(row["curve_x"])
    if row["t_pos"] is not None:
        edge["t"] = float(row["t_pos"])
    return edge


def fetch_graph(db_path=None):
    with get_connection(db_path) as conn:
        nodes = [row_to_node(r) for r in conn.execute("SELECT * FROM nodes ORDER BY rowid").fetchall()]
        edges = [row_to_edge(r) for r in conn.execute("SELECT * FROM edges ORDER BY rowid").fetchall()]
    patched_ids = [e["id"] for e in edges if e["isPatched"]]
    return {"nodes": nodes, "edges": edges, "patchedEdges": patched_ids}


def create_node_with_edges(node_data, edges_data, db_path=None):
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO nodes (id, label, ku_label, role, ku_role, tag, x, y, h)
            VALUES (:id, :label, :kuLabel, :role, :kuRole, :tag, :x, :y, :h)
            """,
            node_data,
        )
        for e in edges_data:
            conn.execute(
                """
                INSERT INTO edges (
                    id, from_node, to_node, cost, vuln, curve_x, t_pos,
                    cvss, severity, vector, cia_c, cia_i, cia_a,
                    technique_en, technique_ku, policy_en, policy_ku,
                    mechanism_en, mechanism_ku, is_patched, patched_at
                ) VALUES (
                    ?, ?, ?, ?, ?, NULL, NULL,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, 0, NULL
                )
                """,
                (
                    e["id"], e["from"], e["to"], e["cost"], e["vuln"],
                    e["cvss"], e["severity"], e["vector"], e["cia"]["c"], e["cia"]["i"], e["cia"]["a"],
                    e["technique"]["en"], e["technique"]["ku"], e["policy"]["en"], e["policy"]["ku"],
                    e["mechanism"]["en"], e["mechanism"]["ku"],
                ),
            )
        conn.commit()
        node_row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_data["id"],)).fetchone()
        edge_rows = [
            conn.execute("SELECT * FROM edges WHERE id = ?", (e["id"],)).fetchone()
            for e in edges_data
        ]
    return row_to_node(node_row), [row_to_edge(r) for r in edge_rows if r is not None]


def update_node_position(node_id, x, y, db_path=None):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE nodes SET x = ?, y = ? WHERE id = ?", (int(x), int(y), node_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return row_to_node(updated)


def set_edge_patched(edge_id, patched_bool, db_path=None):
    now = utc_now() if patched_bool else None
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM edges WHERE id = ?", (edge_id,)).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE edges SET is_patched = ?, patched_at = ? WHERE id = ?",
            (1 if patched_bool else 0, now, edge_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM edges WHERE id = ?", (edge_id,)).fetchone()
        return row_to_edge(updated)


def update_edge_fields(edge_id, cost=None, cvss=None, severity=None, cia=None, db_path=None):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM edges WHERE id = ?", (edge_id,)).fetchone()
        if row is None:
            return None
        new_cost = row["cost"] if cost is None else cost
        new_cvss = row["cvss"] if cvss is None else cvss
        new_sev = row["severity"] if severity is None else severity
        new_c = row["cia_c"] if not cia or "c" not in cia else cia["c"]
        new_i = row["cia_i"] if not cia or "i" not in cia else cia["i"]
        new_a = row["cia_a"] if not cia or "a" not in cia else cia["a"]
        conn.execute(
            """
            UPDATE edges
            SET cost = ?, cvss = ?, severity = ?, cia_c = ?, cia_i = ?, cia_a = ?
            WHERE id = ?
            """,
            (new_cost, new_cvss, new_sev, new_c, new_i, new_a, edge_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM edges WHERE id = ?", (edge_id,)).fetchone()
        return row_to_edge(updated)


def restore_all_edges(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("UPDATE edges SET is_patched = 0, patched_at = NULL")
        conn.commit()


def apply_patched_set(edge_ids, db_path=None):
    valid_set = set(edge_ids)
    now = utc_now()
    with get_connection(db_path) as conn:
        conn.execute("UPDATE edges SET is_patched = 0, patched_at = NULL")
        if valid_set:
            conn.executemany(
                "UPDATE edges SET is_patched = 1, patched_at = ? WHERE id = ?",
                [(now, eid) for eid in valid_set],
            )
        conn.commit()


def add_mitigation_log(edge_id, vuln, action, note="", risk_before=None, risk_after=None, db_path=None):
    now = utc_now()
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO mitigation_logs (edge_id, vuln, action, note, risk_before, risk_after, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (edge_id, vuln, action, note, risk_before, risk_after, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM mitigation_logs WHERE id = ?", (cur.lastrowid,)).fetchone()
        return dict(row)


def fetch_mitigation_logs(limit=30, db_path=None):
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM mitigation_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def record_search_run(result, start_node, goal_node, dls_limit, patched_count, db_path=None):
    now = utc_now()
    cia = result["security"]["cia"]
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO search_runs (
                algo, start_node, goal_node, dls_limit, found, status_key, status_arg,
                path_json, cost, hops, risk_score, risk_severity,
                cia_c, cia_i, cia_a, expanded, max_frontier, patched_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["algo"], start_node, goal_node, dls_limit,
                1 if result["found"] else 0,
                result["statusKey"], result["statusArg"],
                json.dumps(result["path"]),
                result["cost"], result["hops"],
                result["riskScore"], result["riskSeverity"],
                cia["c"]["level"], cia["i"]["level"], cia["a"]["level"],
                result["expanded"], result["maxFrontier"], patched_count, now,
            ),
        )
        conn.commit()
        return cur.lastrowid


def fetch_search_history(limit=25, db_path=None):
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM search_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    history = []
    for r in rows:
        item = dict(r)
        item["found"] = bool(item["found"])
        item["path"] = json.loads(item.pop("path_json"))
        history.append(item)
    return history


def clear_search_history(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM search_runs")
        conn.commit()


def fetch_scenarios(db_path=None):
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM scenarios ORDER BY id DESC").fetchall()
    scenarios = []
    for r in rows:
        item = dict(r)
        item["patchedEdges"] = json.loads(item.pop("patched_edges_json"))
        scenarios.append(item)
    return scenarios


def create_scenario(name, description, start_node, goal_node, algo, dls_limit, patched_edges, risk_score, risk_severity, db_path=None):
    now = utc_now()
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scenarios (
                name, description, start_node, goal_node, algo, dls_limit,
                patched_edges_json, risk_score, risk_severity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name, description, start_node, goal_node, algo, dls_limit,
                json.dumps(sorted(set(patched_edges))), risk_score, risk_severity, now,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scenarios WHERE id = ?", (cur.lastrowid,)).fetchone()
        item = dict(row)
        item["patchedEdges"] = json.loads(item.pop("patched_edges_json"))
        return item


def get_scenario(scenario_id, db_path=None):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["patchedEdges"] = json.loads(item.pop("patched_edges_json"))
    return item


def delete_scenario(scenario_id, db_path=None):
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM scenarios WHERE id = ?", (scenario_id,))
        conn.commit()
        return cur.rowcount > 0


def db_stats(db_path=None):
    target_path = DB_PATH if db_path is None else db_path
    with get_connection(target_path) as conn:
        return {
            "engine": "SQLite",
            "databaseFile": os.path.basename(target_path),
            "nodes": conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
            "edges": conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
            "patchedEdges": conn.execute("SELECT COUNT(*) FROM edges WHERE is_patched = 1").fetchone()[0],
            "searchRuns": conn.execute("SELECT COUNT(*) FROM search_runs").fetchone()[0],
            "mitigationLogs": conn.execute("SELECT COUNT(*) FROM mitigation_logs").fetchone()[0],
            "scenarios": conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0],
        }
