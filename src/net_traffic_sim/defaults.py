"""Default values for the network traffic simulator configuration."""


# ---------------------------------------------------------------------------
# Network infrastructure and identity
# ---------------------------------------------------------------------------

WEB_APP_SERVER_IP = "10.3.10.11"
WEB_APP_HOSTNAME = "portal.corp.local"
SHAREPOINT_SERVER_IP = "10.3.10.15"
SHAREPOINT_HOSTNAME = "sharepoint.corp.local"
SQL_SERVER_IP = "10.3.10.21"
DOMAIN_CONTROLLER_IP = "10.3.10.10"
FILE_SHARE_SERVER_IP = "10.3.10.30"
MAIL_SERVER_IP = "10.3.10.25"
MONITORING_SERVER_IP = "10.3.10.40"
SYSLOG_SERVER_IP = "10.3.10.41"
WSUS_SERVER_IP = "10.3.10.45"
LINUX_SERVER_IP = "10.3.10.60"
FTP_SERVER_IP = "10.3.10.61"
VOIP_PBX_IP = "10.3.10.55"
ATTACKER_PUBLIC_IPS = [
    "203.0.113.100",
    "203.0.113.101",
    "203.0.113.102",
    "203.0.113.103",
]
ATTACKER_PUBLIC_IP = ATTACKER_PUBLIC_IPS[0]
GATEWAY_IP = "10.3.0.1"
GATEWAY_MAC_ADDRESS = "00:1A:A1:B2:C3:D4"

IPV6_PREFIX = "fd00:10:3::"

MAC_VENDOR_OUIS = {
    "workstation": ["00:1B:21", "00:15:17", "00:1E:68", "00:50:8D"],
    "server": ["00:14:22", "00:1A:A0", "00:21:70", "24:6E:96"],
    "router": ["00:1A:A1", "00:23:04", "00:26:0B", "00:50:73"],
    "vm": ["00:15:5D", "00:50:F2"],
    "external": ["00:16:3E", "52:54:00", "00:1C:42"],
}

# ---------------------------------------------------------------------------
# Runtime behavior tuning
# ---------------------------------------------------------------------------

RANDOM_SEED = None
EPHEMERAL_PORT_RANGE = (49152, 65535)

HTTP_KEEPALIVE_TIMEOUT_SECONDS = 120
HTTP_KEEPALIVE_MAX_REQUESTS = 6
HTTP_KEEPALIVE_EARLY_CLOSE_PROBABILITY = 0.20
HTTP_KEEPALIVE_CLOSE_PROBABILITY = 0.10

DHCP_LEASES_PER_HOUR = 4
NTP_QUERIES_PER_HOUR = 6
SNMP_POLLS_PER_MINUTE = 6
SMTP_SESSIONS_PER_HOUR = 4
IMAP_SESSIONS_PER_HOUR = 3
POP3_SESSIONS_PER_HOUR = 2
LLMNR_QUERIES_PER_HOUR = 6
NBNS_QUERIES_PER_HOUR = 4
LDAPS_SESSIONS_PER_HOUR = 3
WINRM_SESSIONS_PER_HOUR = 4
MSRPC_SESSIONS_PER_HOUR = 6
DNS_TCP_QUERIES_PER_HOUR = 10
SSH_SESSIONS_PER_HOUR = 2
FTP_SESSIONS_PER_HOUR = 1
SIP_CALLS_PER_HOUR = 8
SYSLOG_MESSAGES_PER_HOUR = 120
QUIC_SESSIONS_PER_HOUR = 20
IPV6_ND_EVENTS_PER_HOUR = 12

TIME_OF_DAY_MULTIPLIERS = [
    (0, 6, 0.05),
    (6, 8, 0.30),
    (8, 12, 1.00),
    (12, 13, 0.70),
    (13, 17, 1.00),
    (17, 19, 0.50),
    (19, 22, 0.20),
    (22, 24, 0.10),
]
WEEKEND_TRAFFIC_MULTIPLIER = 0.60
PUBLIC_SCANNER_IPS = [
    ATTACKER_PUBLIC_IPS[0],
    ATTACKER_PUBLIC_IPS[1],
    "198.51.100.47",
    "198.51.100.42",
    "198.51.100.89",
    "198.51.100.23",
    "198.51.100.15",
    "198.51.100.203",
    "198.51.100.78",
    "198.51.100.22",
    "198.51.100.28",
    "198.51.100.5",
]

NTP_SERVER_POOL = [
    ("time.windows.com", "192.0.2.10", "LOCL", 3),
    ("time.nist.gov", "192.0.2.20", "NIST", 1),
    ("pool.ntp.org", "192.0.2.30", "POOL", 2),
]

# ---------------------------------------------------------------------------
# Web scanner profiles
# ---------------------------------------------------------------------------

SCANNER_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Mozilla/5.0 (compatible; Nuclei - https://github.com/projectdiscovery/nuclei)",
    "Expanse, a Palo Alto Networks company, searches across the global IPv4 space",
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    "Shodan/1.0",
    "Mozilla/5.0 (compatible; ZoomEye/1.0; +https://www.zoomeye.org/)",
    "Mozilla/5.0 (compatible; zgrab/0.1)",
    "Mozilla/5.0 (compatible; masscan/1.3; https://github.com/robertdavidgraham/masscan)",
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
    "Nikto/2.1.5",
    "WhatWeb/0.5.5",
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "w3af.org",
    "Mozilla/5.0 (compatible; Acunetix/15.2; +https://www.acunetix.com/)",
    "python-requests/2.31.0",
    "python-httpx/0.24.1",
    "Go-http-client/1.1",
    "curl/7.88.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
]

WEB_APP_SCANNER_ENDPOINTS = [
    ("GET", "/", 200),
    ("GET", "/robots.txt", 200),
    ("GET", "/sitemap.xml", 404),
    ("GET", "/favicon.ico", 200),
    ("GET", "/health", 200),
    ("GET", "/status", 200),
    ("GET", "/metrics", 403),
    ("GET", "/.well-known/security.txt", 200),
    ("GET", "/.well-known/change-password", 302),
    ("GET", "/login", 200),
    ("GET", "/signin", 200),
    ("GET", "/logout", 302),
    ("GET", "/sso", 302),
    ("GET", "/oauth/authorize", 302),
    ("POST", "/oauth/token", 401),
    ("GET", "/admin", 403),
    ("GET", "/admin/login", 403),
    ("POST", "/login", 401),
    ("GET", "/api/", 401),
    ("GET", "/api/v1/users", 401),
    ("GET", "/api/v1/status", 200),
    ("POST", "/api/v1/auth", 401),
    ("GET", "/api/v2/", 401),
    ("POST", "/graphql", 401),
    ("GET", "/wp-admin/", 404),
    ("GET", "/phpmyadmin/", 404),
    ("GET", "/.git/config", 404),
    ("GET", "/.env", 404),
    ("GET", "/server-status", 403),
    ("GET", "/actuator/health", 403),
    ("GET", "/actuator/info", 403),
    ("GET", "/old/", 404),
    ("GET", "/backup/", 404),
    ("GET", "/console/", 404),
    ("GET", "/debug/", 404),
]

SHAREPOINT_VULNERABLE_ENDPOINTS = [
    ("GET", "/_api/web", 401),
    ("GET", "/_api/web/siteusers", 401),
    ("GET", "/_api/web/lists", 401),
    ("GET", "/_vti_inf.html", 200),
    ("GET", "/_layouts/15/start.aspx", 302),
    ("GET", "/_layouts/15/Settings.aspx", 403),
    ("GET", "/_layouts/15/ManageFeatures.aspx", 403),
    ("GET", "/_layouts/15/Doc.aspx", 200),
    ("POST", "/_vti_bin/client.svc/ProcessQuery", 403),
    ("GET", "/_vti_bin/ListData.svc", 403),
    ("GET", "/_vti_bin/Lists.asmx", 403),
    ("GET", "/_vti_bin/Views.asmx", 403),
    ("POST", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit", 200),
    ("GET", "/_layouts/15/Authenticate.aspx", 302),
    ("GET", "/_layouts/15/sitemanager.aspx", 403),
]

SCANNER_BEHAVIORS = {
    "aggressive": {
        "requests_per_hour": (20, 40),
        "delay_between_requests": (1, 5),
        "endpoints_targeted": 30,
    },
    "moderate": {
        "requests_per_hour": (8, 15),
        "delay_between_requests": (5, 20),
        "endpoints_targeted": 20,
    },
    "slow": {
        "requests_per_hour": (2, 6),
        "delay_between_requests": (30, 120),
        "endpoints_targeted": 15,
    },
}

WORKSTATION_HOSTS = {
    "IT-WS-01": "10.3.50.11",
    "IT-WS-02": "10.3.50.12",
    "HR-WS-01": "10.3.50.13",
    "HR-WS-02": "10.3.50.14",
    "MKT-WS-01": "10.3.50.15",
    "MKT-WS-02": "10.3.50.16",
    "DEV-WS-01": "10.3.50.17",
    "DEV-WS-02": "10.3.50.18",
    "FIN-WS-01": "10.3.50.19",
    "FIN-WS-02": "10.3.50.20",
    "OPS-WS-01": "10.3.50.21",
    "OPS-WS-02": "10.3.50.22",
    "ENG-WS-01": "10.3.50.23",
    "ENG-WS-02": "10.3.50.24",
    "SALES-WS-01": "10.3.50.25",
    "SUPPORT-WS-01": "10.3.50.28",
}
ADMIN_WORKSTATION_HOSTS = {
    "IT-ADMIN-01": "10.3.30.15",
    "IT-ADMIN-02": "10.3.30.16",
    "SEC-ADMIN-01": "10.3.30.17",
    "SEC-ADMIN-02": "10.3.30.18",
    "IT-ADMIN-03": "10.3.30.19",
}
SERVER_HOSTS = {
    "WEB-SRV01": WEB_APP_SERVER_IP,
    "SQL-SRV01": SQL_SERVER_IP,
    "DC01": DOMAIN_CONTROLLER_IP,
    "FILE-SRV01": FILE_SHARE_SERVER_IP,
    "MAIL-SRV01": MAIL_SERVER_IP,
    "MON-SRV01": MONITORING_SERVER_IP,
    "SYSLOG-SRV01": SYSLOG_SERVER_IP,
    "WSUS-SRV01": WSUS_SERVER_IP,
    "LINUX-SRV01": LINUX_SERVER_IP,
    "FTP-SRV01": FTP_SERVER_IP,
    "VOIP-PBX01": VOIP_PBX_IP,
}
VOIP_PHONE_HOSTS = {
    "VOIP-01": "10.3.60.11",
    "VOIP-02": "10.3.60.12",
    "VOIP-03": "10.3.60.13",
    "VOIP-04": "10.3.60.14",
}
USER_WORKSTATION_IPS = list(WORKSTATION_HOSTS.values())
ADMIN_WORKSTATION_IPS = list(ADMIN_WORKSTATION_HOSTS.values())
VOIP_PHONE_IPS = list(VOIP_PHONE_HOSTS.values())

EXTERNAL_HOST_IPS = [
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "203.0.113.13",
    "203.0.113.14",
    "203.0.113.15",
    "203.0.113.16",
    "203.0.113.17",
    "203.0.113.18",
    "203.0.113.19",
]

EXTERNAL_DNS_IPS = [
    "192.0.2.53",
    "192.0.2.54",
    "198.51.100.53",
    "198.51.100.54",
    "203.0.113.53",
    "203.0.113.54",
]

DEFAULT_CAPTURE_DURATION_MINUTES = 1440
DEFAULT_CAPTURE_DURATION_SECONDS = DEFAULT_CAPTURE_DURATION_MINUTES * 60

SQL_QUERIES_PER_SEC = 1
HTTP_REQUESTS_PER_SEC = 30
DNS_QUERIES_PER_SEC = 20
DEFAULT_SMB_SIMULATED_SIZE_MB = 20
RETRANSMISSION_RATE_SQL = 0.20
RETRANSMISSION_RATE_OTHER = 0.015

TCP_WINDOW_SQL_CLIENT = [1021, 1022, 1023, 1024, 1025, 1026, 1027, 2046, 2047, 2048]
TCP_WINDOW_SQL_SERVER = [8190, 8191, 8192, 8193, 8194, 8195, 16383, 16384, 32768]
TCP_WINDOW_RDP_CLIENT = 15082
TCP_WINDOW_RDP_SERVER = list(range(62816, 64001, 74))
TCP_WINDOW_HTTPS = [65535, 65280, 65024]
TCP_WINDOW_SMB_CLIENT = 8192
TCP_WINDOW_SMB_SERVER = 16384

TDS_RPC_SIZES = [253, 283, 306, 322, 380, 390, 409, 551, 557, 586, 599, 667, 810, 812, 1131, 1154]
TDS_RESPONSE_SIZES = [90, 113, 119, 128, 136, 145, 161, 472, 534, 544, 546, 548, 552]
TDS_BATCH_SIZES = [283, 586, 667]

RDP_CLIENT_SIZES = [74, 109, 132, 150]
RDP_SERVER_SIZES = [267, 273, 301, 307, 312, 323, 324, 325, 327, 328, 331, 334, 336, 339, 347, 355, 357, 362, 386, 397]

EXTERNAL_DOMAINS = [
    "reuters.com",
    "bloomberg.com",
    "techcrunch.net",
    "financialtimes.co.uk",
    "theguardian.com",
    "wsj.com",
    "forbes.com",
    "businessinsider.com",
    "cnet.com",
    "zdnet.com",
    "arstechnica.com",
    "theregister.com",
    "wired.com",
    "engadget.com",
    "gizmodo.com",
    "theverge.com",
    "securityweek.com",
    "bleepingcomputer.com",
    "threatpost.com",
    "darkreading.com",
    "cloudfront.net",
    "akamaihd.net",
    "azureedge.net",
    "fastly.net",
    "cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.com",
    "cdn77.com",
    "bunnycdn.com",
    "edgecast.net",
    "limelight.net",
    "highwinds.com",
    "cdninstagram.com",
    "fbcdn.net",
    "twimg.com",
    "ytimg.com",
    "imgur.com",
    "staticflickr.com",
    "wp.com",
    "gravatar.com",
    "disqus.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "adroll.com",
    "quantserve.com",
    "office365.microsoft.com",
    "login.microsoftonline.com",
    "outlook.office365.com",
    "onedrive.live.com",
    "api.office.com",
    "graph.microsoft.com",
    "management.azure.com",
    "portal.azure.com",
    "windows.microsoft.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "windowsupdate.microsoft.com",
    "fe2.update.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    "msedge.net",
    "bing.com",
    "live.com",
    "outlook.com",
    "teams.microsoft.com",
    "skype.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "ocsp.digicert.com",
    "ctldl.windowsupdate.com",
    "api.dropbox.com",
    "dropbox.com",
    "dl.dropboxusercontent.com",
    "slack.com",
    "api.slack.com",
    "files.slack.com",
    "zoom.us",
    "api.zoom.us",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "github.githubassets.com",
    "gitlab.com",
    "bitbucket.org",
    "aws.amazon.com",
    "s3.amazonaws.com",
    "ec2.amazonaws.com",
    "console.cloud.google.com",
    "storage.googleapis.com",
    "api.salesforce.com",
    "salesforce.com",
    "atlassian.net",
    "jira.atlassian.com",
    "confluence.atlassian.com",
    "zendesk.com",
    "api.zendesk.com",
    "hubspot.com",
    "intercom.io",
    "drift.com",
    "docker.io",
    "registry.hub.docker.com",
    "client-portal.acmecorp.com",
    "vendor.supplychainsys.net",
    "erp.manufacturing-intl.com",
    "billing.enterprise-solutions.com",
    "api.logistics-partners.com",
    "portal.financialservices-group.com",
    "dashboard.hr-management-pro.com",
    "app.crm-enterprise.com",
    "secure.payroll-systems.com",
    "admin.it-asset-manager.com",
    "vpn.consulting-firm.com",
    "remote.legal-services.com",
    "cloud.backup-solutions.com",
    "api.monitoring-service.com",
    "portal.compliance-software.com",
    "app.audit-platform.com",
    "dashboard.analytics-enterprise.com",
    "api.data-warehouse.com",
    "secure.identity-provider.com",
    "sso.enterprise-auth.com",
    "mail.business-partner-a.com",
    "webmail.supplier-b.com",
    "ftp.vendor-c.com",
    "sftp.partner-d.com",
    "api.payment-gateway.com",
    "secure.merchant-services.com",
    "portal.insurance-provider.com",
    "claims.healthcare-system.com",
    "booking.travel-corporate.com",
    "expense.finance-tracker.com",
    "training.elearning-platform.com",
    "lms.corporate-university.com",
    "helpdesk.it-support-pro.com",
    "tickets.service-desk.com",
    "repository.software-vendor.com",
    "downloads.enterprise-app.com",
    "licensing.software-company.com",
    "activation.product-server.com",
    "api.integration-platform.com",
    "webhook.automation-service.com",
    "updates.antivirus-vendor.com",
    "definitions.malware-protection.com",
    "threat-intel.security-company.net",
    "ioc.threat-database.com",
    "crl.certprovider.com",
    "ocsp.ca-authority.com",
    "revocation.pki-services.com",
    "timestamp.signing-authority.com",
    "ntp.pool.org",
    "time.nist.gov",
    "time.windows.com",
    "dns.quad9.net",
    "one.one.one.one",
    "vpn-gateway.remote-access.com",
    "sslvpn.corporate-wan.com",
    "firewall-updates.network-security.com",
    "ips-signatures.intrusion-detection.com",
    "siem.security-operations.com",
    "splunk.enterprise-logging.com",
    "elk.log-aggregator.com",
    "wikipedia.org",
    "stackoverflow.com",
    "reddit.com",
    "medium.com",
    "linkedin.com",
    "twitter.com",
    "facebook.com",
    "youtube.com",
    "amazon.com",
    "ebay.com",
    "paypal.com",
    "stripe.com",
    "adobe.com",
    "docker.com",
    "npmjs.com",
    "pypi.org",
    "ubuntu.com",
    "debian.org",
    "centos.org",
    "redhat.com",
    "oracle.com",
    "mysql.com",
    "postgresql.org",
    "mongodb.com",
    "apache.org",
    "nginx.org",
    "iis.net",
    "w3.org",
    "ietf.org",
    "ieee.org",
    "iso.org",
    "cert.org",
    "cve.mitre.org",
    "nvd.nist.gov",
    "virustotal.com",
    "shodan.io",
]

FILE_TRANSFERS = [
    ("Q3_Financial_Report.xlsx", 2_400_000, "http", "10.3.10.11", "10.3.50.12"),
    ("Q4_Budget_Forecast.xlsx", 1_900_000, "http", "10.3.10.11", "10.3.50.15"),
    ("ProjectProposal_Draft_v3.docx", 460_000, "http", "10.3.10.11", "10.3.50.18"),
    ("ClientPresentation_Final.pptx", 9_100_000, "http", "10.3.10.11", "10.3.50.22"),
    ("Marketing_Strategy_2025.pptx", 12_700_000, "http", "10.3.10.11", "10.3.50.14"),
    ("Meeting_Notes_Oct2025.docx", 130_000, "http", "10.3.10.11", "10.3.50.11"),
    ("Employee_Handbook_2025.pdf", 12_600_000, "http", "10.3.10.11", "10.3.50.25"),
    ("Compliance_Policy_Update.pdf", 3_200_000, "http", "10.3.10.11", "10.3.50.19"),
    ("Security_Awareness_Training.pdf", 5_900_000, "http", "10.3.10.11", "10.3.50.28"),
    ("CompanyLogo_HighRes.png", 1_900_000, "http", "10.3.10.11", "10.3.50.13"),
    ("7zip_x64_23.01.exe", 1_570_000, "http", "10.3.10.11", "10.3.50.11"),
    ("Notepad++_8.5.8_x64.exe", 4_200_000, "http", "10.3.10.11", "10.3.50.19"),
    ("PuTTY_0.79_x64.exe", 3_100_000, "http", "10.3.10.11", "10.3.30.15"),
    ("WinSCP_6.2.2_Setup.exe", 11_900_000, "http", "10.3.10.11", "10.3.30.17"),
    ("TreeSize_Free_4.7.exe", 6_200_000, "http", "10.3.10.11", "10.3.50.20"),
    ("vcredist_x64_2015-2022.exe", 14_700_000, "http", "10.3.10.11", "10.3.50.21"),
    ("DirectX_Web_Installer.exe", 290_000, "http", "10.3.10.11", "10.3.50.23"),
    ("Portal_WebParts_v2.3.zip", 12_400_000, "http", "10.3.10.11", "10.3.30.15"),
    ("PowerShell_Scripts_Collection.zip", 3_200_000, "http", "10.3.10.11", "10.3.30.17"),
    ("IIS_Configuration_Templates.zip", 890_000, "http", "10.3.10.11", "10.3.30.15"),
    ("SQL_Maintenance_Scripts.zip", 1_200_000, "http", "10.3.10.11", "10.3.30.16"),
    ("AD_Group_Policy_Backup.zip", 8_900_000, "http", "10.3.10.11", "10.3.30.18"),
    ("Monitoring_Scripts_Bundle.zip", 4_500_000, "http", "10.3.10.11", "10.3.30.17"),
    ("Certificate_Management_Tools.zip", 6_700_000, "http", "10.3.10.11", "10.3.30.18"),
    ("Backup_Scripts_October.zip", 2_100_000, "http", "10.3.10.11", "10.3.30.16"),
    ("Deployment_Automation_v3.2.zip", 9_800_000, "http", "10.3.10.11", "10.3.30.15"),
    ("msvcr120.dll", 970_000, "http", "10.3.10.11", "10.3.50.18"),
    ("msvcp140.dll", 570_000, "http", "10.3.10.11", "10.3.50.22"),
    ("vcruntime140.dll", 85_000, "http", "10.3.10.11", "10.3.50.15"),
    ("concrt140.dll", 280_000, "http", "10.3.10.11", "10.3.50.19"),
    ("Win11_Enterprise_23H2.iso", 5_400_000_000, "smb", "10.3.10.30", "10.3.50.22"),
    ("KB5034441_x64.msu", 930_000_000, "smb", "10.3.10.30", "10.3.10.11"),
    ("KB5034442_x64.msu", 685_000_000, "smb", "10.3.10.30", "10.3.10.21"),
    ("Office365_ProPlus_x64.exe", 3_350_000_000, "smb", "10.3.10.30", "10.3.50.25"),
    ("Docker_Desktop_4.25.2_x64.exe", 534_000_000, "smb", "10.3.10.30", "10.3.30.19"),
    ("Chrome_Enterprise_119.0_x64.msi", 163_000_000, "smb", "10.3.10.30", "10.3.50.14"),
    ("Firefox_ESR_115.5.0_x64.exe", 70_000_000, "smb", "10.3.10.30", "10.3.50.19"),
    ("Teams_2.1.4.0_x64.msi", 135_000_000, "smb", "10.3.10.30", "10.3.50.13"),
    ("Slack_4.35.126_x64.exe", 119_000_000, "smb", "10.3.10.30", "10.3.50.24"),
    ("Java_JDK_21.0.1_x64.exe", 178_000_000, "smb", "10.3.10.30", "10.3.30.19"),
    ("Python_3.11.6_x64.exe", 29_000_000, "smb", "10.3.10.30", "10.3.30.16"),
    ("PowerShell_7.4.0_x64.msi", 103_000_000, "smb", "10.3.10.30", "10.3.30.17"),
    ("Sysinternals_Suite_2023-11.zip", 35_600_000, "smb", "10.3.10.30", "10.3.30.18"),
    ("Windows_Admin_Tools.zip", 18_700_000, "smb", "10.3.10.30", "10.3.30.19"),
    ("UpdateRollup_KB5034_Offline.zip", 678_000_000, "smb", "10.3.10.30", "10.3.30.16"),
    ("Office_Shared_Components.cab", 45_000_000, "smb", "10.3.10.30", "10.3.50.28"),
    ("SQL_Backup_Daily_20251029.bak", 2_410_000_000, "smb", "10.3.10.21", "10.3.10.30"),
    ("Portal_ContentDB_Backup.bak", 4_930_000_000, "smb", "10.3.10.11", "10.3.10.30"),
    ("IIS_Logs_Archive_Oct.zip", 312_000_000, "smb", "10.3.10.11", "10.3.10.30"),
    ("EventLogs_Archive.evtx", 70_200_000, "smb", "10.3.10.21", "10.3.10.30"),
    ("Security_Scan_Results.pdf", 23_000_000, "smb", "10.3.30.18", "10.3.10.30"),
]
