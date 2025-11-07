"""Phase 3: Comprehensive query templates for MITRE ATT&CK techniques.

This module contains an expanded collection of detection templates covering
multiple MITRE ATT&CK tactics and techniques across all supported EDR platforms.
"""

# Template format: (technique_id, platform, query_template, variables, confidence, false_positive_notes, data_sources)

PHASE3_TEMPLATES = [
    # ===== PROCESS EXECUTION =====

    # T1059.003 - Windows Command Shell
    (
        "T1059.003",
        "defender",
        """// MITRE ATT&CK T1059.003 - Windows Command Shell
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any (
    "/c ", "copy ", "net user", "net localgroup",
    "reg add", "sc create", "wmic ", "taskkill"
)
{% if ips %}
| where ProcessCommandLine has_any ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| where InitiatingProcessFileName !in~ ("explorer.exe", "services.exe")
| extend SuspiciousPattern = case(
    ProcessCommandLine contains "net user" and ProcessCommandLine contains "/add", "UserCreation",
    ProcessCommandLine contains "reg add" and ProcessCommandLine contains "Run", "PersistenceRegistry",
    ProcessCommandLine contains "wmic process call create", "RemoteExecution",
    "General"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, SuspiciousPattern
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "cmd.exe is widely used. Focus on commands from unusual parent processes or with suspicious parameters.",
        ["Process", "Command Line"]
    ),

    (
        "T1059.003",
        "crowdstrike",
        """// MITRE ATT&CK T1059.003 - Windows Command Shell
#event_simpleName=ProcessRollup2
| ImageFileName=/cmd\\.exe/i
| CommandLine=/(net user|net localgroup|reg add|sc create|wmic|taskkill)/i
| groupBy([ComputerName, CommandLine, ParentBaseFileName], function=[count(as=Events), collect([UserName])])
| Events > 0""",
        {},
        "medium",
        "Common in Windows environments. Focus on suspicious parent processes and command combinations.",
        ["Process"]
    ),

    # T1059.005 - Visual Basic
    (
        "T1059.005",
        "defender",
        """// MITRE ATT&CK T1059.005 - Visual Basic Malicious Execution
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName in~ ("cscript.exe", "wscript.exe", "mshta.exe")
| where ProcessCommandLine has_any (".vbs", ".vbe", ".js", ".jse", ".hta")
{% if hashes %}
| where SHA256 in ({% for hash in hashes %}"{{ hash }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| extend ScriptType = case(
    ProcessCommandLine contains ".vbs", "VBScript",
    ProcessCommandLine contains ".js", "JavaScript",
    ProcessCommandLine contains ".hta", "HTA",
    "Other"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ScriptType
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "Scripting engines are often abused. Validate scripts against known good applications.",
        ["Process", "Command Line", "File"]
    ),

    (
        "T1059.005",
        "carbonblack",
        """// MITRE ATT&CK T1059.005 - Visual Basic
(process_name:cscript.exe OR process_name:wscript.exe OR process_name:mshta.exe)
AND (
  process_cmdline:*.vbs OR
  process_cmdline:*.vbe OR
  process_cmdline:*.js OR
  process_cmdline:*.jse OR
  process_cmdline:*.hta
)""",
        {},
        "high",
        "Scripts can be legitimate. Investigate unknown or suspicious script paths.",
        ["Process"]
    ),

    # ===== PERSISTENCE =====

    # T1547.001 - Registry Run Keys
    (
        "T1547.001",
        "defender",
        """// MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceRegistryEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RegistryKey has_any (
    @"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    @"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    @"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    @"\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where not(RegistryValueData has_any ("Microsoft", "Adobe", "Google"))  // Adjust for your environment
{% if file_names %}
| where RegistryValueData has_any ({% for name in file_names %}"{{ name }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| extend PersistencePath = RegistryValueData
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, PersistencePath
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "Legitimate software uses Run keys. Focus on unknown executables or unusual paths.",
        ["Registry"]
    ),

    (
        "T1547.001",
        "crowdstrike",
        """// MITRE ATT&CK T1547.001 - Registry Run Keys
#event_simpleName=RegKeySecurityApplied OR #event_simpleName=RegStringValueUpdate
| RegValueName=/Run|RunOnce/i
| RegObjectPath=/CurrentVersion\\\\Run/i
| groupBy([ComputerName, RegObjectPath, RegValueName, RegStringValue], function=count(as=Events))
| Events > 0""",
        {},
        "high",
        "Common persistence mechanism. Validate against software installation logs.",
        ["Registry"]
    ),

    # T1547.009 - Shortcut Modification
    (
        "T1547.009",
        "defender",
        """// MITRE ATT&CK T1547.009 - Shortcut Modification
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceFileEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName endswith ".lnk"
| where FolderPath has_any (
    "\\Start Menu\\",
    "\\Startup\\",
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"
)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName !in~ ("explorer.exe", "setup.exe", "msiexec.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "Shortcuts are modified by installers. Focus on modifications by unusual processes.",
        ["File"]
    ),

    # ===== CREDENTIAL ACCESS =====

    # T1003.001 - LSASS Memory Dumping
    (
        "T1003.001",
        "defender",
        """// MITRE ATT&CK T1003.001 - LSASS Memory Dumping
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where (FileName =~ "procdump.exe" or FileName =~ "procdump64.exe")
    and ProcessCommandLine contains "lsass"
or (FileName =~ "rundll32.exe"
    and ProcessCommandLine has_all ("comsvcs.dll", "MiniDump"))
or ProcessCommandLine has_all ("lsass", "dump")
| extend DumpMethod = case(
    FileName =~ "procdump.exe", "ProcDump",
    ProcessCommandLine contains "comsvcs.dll", "Rundll32_Comsvcs",
    ProcessCommandLine contains "MiniDump", "MiniDumpWriteDump",
    "Other"
)
{% if hashes %}
| where SHA256 in ({% for hash in hashes %}"{{ hash }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, DumpMethod
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "High confidence indicator. Validate against authorized security tools and incident response activity.",
        ["Process", "Command Line"]
    ),

    (
        "T1003.001",
        "sentinelone",
        """// MITRE ATT&CK T1003.001 - LSASS Memory Dumping
EventType = "Process Creation" AND
(
  (SrcProcName In ("procdump.exe", "procdump64.exe") AND SrcProcCmdLine ContainsCIS "lsass") OR
  (SrcProcName = "rundll32.exe" AND SrcProcCmdLine ContainsCIS "comsvcs.dll" AND SrcProcCmdLine ContainsCIS "MiniDump") OR
  (SrcProcCmdLine ContainsCIS "lsass" AND SrcProcCmdLine ContainsCIS "dump")
)""",
        {},
        "high",
        "Critical detection. Investigate immediately unless part of authorized security operations.",
        ["Process"]
    ),

    # T1003.002 - Security Account Manager (SAM)
    (
        "T1003.002",
        "defender",
        """// MITRE ATT&CK T1003.002 - SAM Database Access
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceFileEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FolderPath has_any (
    @"\\Windows\\System32\\config\\SAM",
    @"\\Windows\\System32\\config\\SYSTEM",
    @"\\Windows\\System32\\config\\SECURITY"
)
| where ActionType in ("FileCreated", "FileModified", "FileCopied")
| where InitiatingProcessFileName !in~ ("smss.exe", "services.exe", "lsass.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "SAM access is highly suspicious. Validate against system backup operations.",
        ["File"]
    ),

    # T1558.003 - Kerberoasting
    (
        "T1558.003",
        "defender",
        """// MITRE ATT&CK T1558.003 - Kerberoasting Detection
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ActionType == "KerberosTicketRequest"
| where AdditionalFields has "RC4" or AdditionalFields has "0x17"
| summarize
    RequestCount = count(),
    UniqueAccounts = dcount(AccountName),
    Services = make_set(tostring(AdditionalFields), 10)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where RequestCount > 5
| project Timestamp, DeviceName, InitiatingProcessFileName, RequestCount, UniqueAccounts, Services
| order by RequestCount desc""",
        {"timeframe": "7d"},
        "medium",
        "Multiple RC4 ticket requests may indicate Kerberoasting. Correlate with unusual service account activity.",
        ["Authentication"]
    ),

    # ===== LATERAL MOVEMENT =====

    # T1021.002 - SMB/Windows Admin Shares
    (
        "T1021.002",
        "defender",
        """// MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort == 445 or RemotePort == 139
| where ActionType == "ConnectionSuccess"
{% if ips %}
| where RemoteIP in ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| summarize
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    FirstConnection = min(Timestamp),
    LastConnection = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, AccountName
| where ConnectionCount > 10 or UniqueDestinations > 5
| extend SuspicionScore = case(
    UniqueDestinations > 10, "High",
    ConnectionCount > 20, "Medium",
    "Low"
)
| project DeviceName, InitiatingProcessFileName, AccountName, ConnectionCount, UniqueDestinations, FirstConnection, LastConnection, SuspicionScore
| order by SuspicionScore desc, UniqueDestinations desc""",
        {"timeframe": "7d"},
        "medium",
        "SMB is common in networks. Focus on connections to many unique destinations or unusual patterns.",
        ["Network"]
    ),

    (
        "T1021.002",
        "crowdstrike",
        """// MITRE ATT&CK T1021.002 - SMB/Windows Admin Shares
#event_simpleName=NetworkConnectIP4
| RemotePort=445 OR RemotePort=139
| groupBy([ComputerName, UserName, RemoteAddressIP4], function=[count(as=Connections), values(LocalAddressIP4)])
| Connections > 5""",
        {},
        "medium",
        "Normal in domain environments. Investigate connections from unusual hosts or accounts.",
        ["Network"]
    ),

    # T1021.006 - Windows Remote Management
    (
        "T1021.006",
        "defender",
        """// MITRE ATT&CK T1021.006 - Windows Remote Management
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort in (5985, 5986)  // WinRM HTTP/HTTPS
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    Destinations = make_set(RemoteIP, 20)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 1h)
| where ConnectionCount > 3 or UniqueDestinations > 3
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ConnectionCount, UniqueDestinations, Destinations
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "WinRM is used for remote administration. Focus on unusual source systems or mass connections.",
        ["Network"]
    ),

    # ===== DEFENSE EVASION =====

    # T1070.001 - Clear Windows Event Logs
    (
        "T1070.001",
        "defender",
        """// MITRE ATT&CK T1070.001 - Clear Windows Event Logs
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has "cl")
    or (ProcessCommandLine has "Clear-EventLog")
| extend LogCleared = extract(@"cl\\s+([\\w-]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, LogCleared, AccountName
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "Log clearing is highly suspicious outside of authorized maintenance windows.",
        ["Process", "Command Line"]
    ),

    (
        "T1070.001",
        "carbonblack",
        """// MITRE ATT&CK T1070.001 - Clear Windows Event Logs
process_name:wevtutil.exe AND process_cmdline:*cl* OR
process_cmdline:*Clear-EventLog*""",
        {},
        "high",
        "Critical indicator. Immediate investigation required.",
        ["Process"]
    ),

    # T1070.004 - File Deletion
    (
        "T1070.004",
        "defender",
        """// MITRE ATT&CK T1070.004 - Indicator Removal on Host: File Deletion
// Confidence: Low
// Timeframe: {{ timeframe | default('24h') }}

DeviceFileEvents
| where Timestamp > ago({{ timeframe | default('24h') }})
| where ActionType == "FileDeleted"
| where FileName has_any (".log", ".evtx", ".txt")
| where FolderPath has_any ("\\Logs\\", "\\Temp\\", "\\Windows\\System32\\winevt\\")
| summarize
    DeletedFiles = count(),
    FileList = make_set(FileName, 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where DeletedFiles > 10
| project Timestamp, DeviceName, InitiatingProcessFileName, DeletedFiles, FileList
| order by DeletedFiles desc""",
        {"timeframe": "24h"},
        "low",
        "File deletion is common. Focus on mass deletion events or deletion of log files.",
        ["File"]
    ),

    # T1562.001 - Disable or Modify Tools
    (
        "T1562.001",
        "defender",
        """// MITRE ATT&CK T1562.001 - Impair Defenses: Disable or Modify Tools
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "Set-MpPreference",
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableIOAVProtection",
    "sc stop",
    "sc delete"
)
and ProcessCommandLine has_any ("WinDefend", "MpsSvc", "Sense")
or ProcessCommandLine has_any ("netsh advfirewall", "off")
| extend DefenseAction = case(
    ProcessCommandLine contains "DisableRealtimeMonitoring", "DisableAV",
    ProcessCommandLine contains "sc stop", "StopService",
    ProcessCommandLine contains "netsh advfirewall", "DisableFirewall",
    "Other"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, DefenseAction, AccountName
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "Disabling security tools is a strong indicator of malicious activity. Investigate immediately.",
        ["Process", "Command Line"]
    ),

    (
        "T1562.001",
        "sentinelone",
        """// MITRE ATT&CK T1562.001 - Disable or Modify Tools
EventType = "Process Creation" AND
(
  SrcProcCmdLine ContainsCIS "Set-MpPreference" OR
  SrcProcCmdLine ContainsCIS "DisableRealtimeMonitoring" OR
  SrcProcCmdLine ContainsCIS "DisableBehaviorMonitoring" OR
  (SrcProcCmdLine ContainsCIS "sc stop" AND SrcProcCmdLine ContainsCIS "WinDefend") OR
  SrcProcCmdLine ContainsCIS "netsh advfirewall"
)""",
        {},
        "high",
        "Critical indicator. Validate against authorized maintenance or policy changes.",
        ["Process"]
    ),

    # ===== DISCOVERY =====

    # T1087.001 - Account Discovery: Local Account
    (
        "T1087.001",
        "defender",
        """// MITRE ATT&CK T1087.001 - Account Discovery: Local Account
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "net user",
    "net localgroup",
    "Get-LocalUser",
    "Get-LocalGroupMember"
)
| where not(InitiatingProcessFileName in~ ("setup.exe", "msiexec.exe"))
| summarize
    EnumerationCount = count(),
    Commands = make_set(ProcessCommandLine, 10)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 1h)
| where EnumerationCount > 3
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, EnumerationCount, Commands
| order by EnumerationCount desc""",
        {"timeframe": "7d"},
        "low",
        "Account enumeration can be legitimate. Focus on unusual processes or excessive enumeration.",
        ["Process", "Command Line"]
    ),

    (
        "T1087.001",
        "carbonblack",
        """// MITRE ATT&CK T1087.001 - Account Discovery
process_cmdline:"net user" OR
process_cmdline:"net localgroup" OR
process_cmdline:"Get-LocalUser" OR
process_cmdline:"Get-LocalGroupMember"
AND NOT parent_name:explorer.exe""",
        {},
        "low",
        "Common in reconnaissance. Correlate with other discovery activity.",
        ["Process"]
    ),

    # T1018 - Remote System Discovery
    (
        "T1018",
        "defender",
        """// MITRE ATT&CK T1018 - Remote System Discovery
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "net view",
    "ping ",
    "nltest /dclist",
    "Get-ADComputer"
)
| summarize
    DiscoveryCount = count(),
    UniqueCommands = dcount(ProcessCommandLine),
    Commands = make_set(ProcessCommandLine, 10)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 5m)
| where DiscoveryCount > 5
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, DiscoveryCount, UniqueCommands, Commands
| order by DiscoveryCount desc""",
        {"timeframe": "7d"},
        "low",
        "Network discovery is common. Focus on rapid or automated discovery patterns.",
        ["Process", "Command Line"]
    ),

    # T1082 - System Information Discovery
    (
        "T1082",
        "defender",
        """// MITRE ATT&CK T1082 - System Information Discovery
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName in~ ("systeminfo.exe", "hostname.exe", "whoami.exe")
    or ProcessCommandLine has_any (
        "Get-ComputerInfo",
        "Get-WmiObject Win32",
        "wmic computersystem"
    )
| summarize
    InfoGatheringCount = count(),
    Tools = make_set(FileName, 10)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 5m)
| where InfoGatheringCount > 3
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, InfoGatheringCount, Tools
| order by InfoGatheringCount desc""",
        {"timeframe": "7d"},
        "low",
        "System info gathering can be legitimate. Focus on rapid sequential execution or unusual parent processes.",
        ["Process", "Command Line"]
    ),

    # ===== COLLECTION =====

    # T1560.001 - Archive via Utility
    (
        "T1560.001",
        "defender",
        """// MITRE ATT&CK T1560.001 - Archive Collected Data: Archive via Utility
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName in~ ("7z.exe", "winrar.exe", "rar.exe", "zip.exe")
    or ProcessCommandLine has_any ("Compress-Archive", "tar -", "makecab")
| where ProcessCommandLine has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| extend ArchiveSize = extract(@"-v([0-9]+[kmg])", 1, ProcessCommandLine)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ArchiveSize
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "Archiving is common. Focus on large archives, unusual locations, or password-protected archives.",
        ["Process", "Command Line"]
    ),

    (
        "T1560.001",
        "crowdstrike",
        """// MITRE ATT&CK T1560.001 - Archive via Utility
#event_simpleName=ProcessRollup2
| ImageFileName=/(7z|winrar|rar|zip)\\.exe/i
| CommandLine=/(\\.zip|\\.rar|\\.7z|\\.tar)/i
| groupBy([ComputerName, ImageFileName, CommandLine], function=count(as=Events))
| Events > 0""",
        {},
        "medium",
        "Investigate archives created in unusual locations or with suspicious names.",
        ["Process"]
    ),

    # T1113 - Screen Capture
    (
        "T1113",
        "defender",
        """// MITRE ATT&CK T1113 - Screen Capture
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "screenshot",
    "screencapture",
    "[System.Drawing.Bitmap]",
    "Graphics]::FromImage"
)
or FileName in~ ("snippingtool.exe", "psr.exe")  // Problem Steps Recorder
| where InitiatingProcessFileName !in~ ("explorer.exe", "teams.exe", "slack.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "Screen capture tools are used legitimately. Focus on captures by unusual processes.",
        ["Process", "Command Line"]
    ),

    # T1005 - Data from Local System
    (
        "T1005",
        "defender",
        """// MITRE ATT&CK T1005 - Data from Local System
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceFileEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName has_any (".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf")
| where ActionType in ("FileCopied", "FileRenamed")
| where FolderPath has_any (
    "\\Users\\",
    "\\Documents\\",
    "\\Desktop\\"
)
| where InitiatingProcessFileName !in~ ("explorer.exe", "OneDrive.exe", "Dropbox.exe")
| summarize
    FileAccessCount = count(),
    UniqueFiles = dcount(FileName),
    Files = make_set(FileName, 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where FileAccessCount > 20
| project Timestamp, DeviceName, InitiatingProcessFileName, FileAccessCount, UniqueFiles, Files
| order by FileAccessCount desc""",
        {"timeframe": "7d"},
        "low",
        "File access is normal. Focus on rapid mass file access by unusual processes.",
        ["File"]
    ),

    # ===== EXFILTRATION =====

    # T1041 - Exfiltration Over C2 Channel
    (
        "T1041",
        "defender",
        """// MITRE ATT&CK T1041 - Exfiltration Over C2 Channel
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort in (80, 443, 8080, 8443)
{% if ips %}
| where RemoteIP in ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
{% if domains %}
| where RemoteUrl has_any ({% for domain in domains %}"{{ domain }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| summarize
    TotalBytesSent = sum(BytesSent),
    TotalBytesReceived = sum(BytesReceived),
    ConnectionCount = count()
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, bin(Timestamp, 1h)
| where TotalBytesSent > 10000000  // >10MB
| extend DataExfilMB = round(TotalBytesSent / 1024.0 / 1024.0, 2)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, DataExfilMB, ConnectionCount
| order by DataExfilMB desc""",
        {"timeframe": "7d"},
        "medium",
        "Large data transfers can be legitimate. Focus on unusual destinations or processes.",
        ["Network"]
    ),

    (
        "T1041",
        "crowdstrike",
        """// MITRE ATT&CK T1041 - Exfiltration Over C2 Channel
#event_simpleName=NetworkConnectIP4
| RemotePort IN [80, 443, 8080, 8443]
| groupBy([ComputerName, RemoteAddressIP4, ImageFileName], function=[sum(TotalBytesWritten, as=BytesSent), count(as=Connections)])
| BytesSent > 10000000""",
        {},
        "medium",
        "High volume data transfer. Correlate with threat intel on known C2 infrastructure.",
        ["Network"]
    ),

    # T1567.002 - Exfiltration to Cloud Storage
    (
        "T1567.002",
        "defender",
        """// MITRE ATT&CK T1567.002 - Exfiltration to Cloud Storage
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemoteUrl has_any (
    "dropbox.com",
    "drive.google.com",
    "onedrive.live.com",
    "box.com",
    "mega.nz",
    "wetransfer.com",
    "file.io",
    "anonfiles.com"
)
| where not(InitiatingProcessFileName in~ ("OneDrive.exe", "Dropbox.exe", "GoogleDrive.exe"))
| summarize
    TotalBytesSent = sum(BytesSent),
    ConnectionCount = count(),
    Services = make_set(RemoteUrl, 10)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 1h)
| where TotalBytesSent > 5000000  // >5MB
| extend DataUploadMB = round(TotalBytesSent / 1024.0 / 1024.0, 2)
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, DataUploadMB, ConnectionCount, Services
| order by DataUploadMB desc""",
        {"timeframe": "7d"},
        "low",
        "Cloud storage use is common. Focus on uploads from unusual processes or to unapproved services.",
        ["Network"]
    ),

    (
        "T1567.002",
        "carbonblack",
        """// MITRE ATT&CK T1567.002 - Exfiltration to Cloud Storage
netconn_domain:(dropbox.com OR drive.google.com OR mega.nz OR wetransfer.com OR anonfiles.com OR file.io)
AND NOT process_name:(OneDrive.exe OR Dropbox.exe OR GoogleDrive.exe)""",
        {},
        "low",
        "Monitor for unauthorized cloud storage use or data exfiltration patterns.",
        ["Network"]
    ),

    # T1048.003 - Exfiltration Over Alternative Protocol
    (
        "T1048.003",
        "defender",
        """// MITRE ATT&CK T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort in (21, 22, 23, 25, 53, 69)  // FTP, SSH, Telnet, SMTP, DNS, TFTP
| where ActionType == "ConnectionSuccess"
| where not(InitiatingProcessFileName in~ ("ssh.exe", "pscp.exe", "winscp.exe", "FileZilla.exe"))
| summarize
    ConnectionCount = count(),
    BytesSent = sum(BytesSent),
    UniqueDestinations = dcount(RemoteIP),
    Destinations = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessFileName, RemotePort, bin(Timestamp, 1h)
| where BytesSent > 1000000 or ConnectionCount > 10
| extend DataSentMB = round(BytesSent / 1024.0 / 1024.0, 2)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemotePort, ConnectionCount, DataSentMB, UniqueDestinations, Destinations
| order by DataSentMB desc""",
        {"timeframe": "7d"},
        "medium",
        "Alternative protocols for data transfer are suspicious. Validate against legitimate file transfer activities.",
        ["Network"]
    ),

    # ===== COMMAND AND CONTROL =====

    # T1071.001 - Web Protocols
    (
        "T1071.001",
        "defender",
        """// MITRE ATT&CK T1071.001 - Application Layer Protocol: Web Protocols
// Confidence: Low
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "Teams.exe", "Slack.exe", "OneDrive.exe"
)
{% if ips %}
| where RemoteIP in ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
{% if domains %}
| where RemoteUrl has_any ({% for domain in domains %}"{{ domain }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| summarize
    ConnectionCount = count(),
    BytesSent = sum(BytesSent),
    BytesReceived = sum(BytesReceived),
    UniqueIPs = dcount(RemoteIP)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, bin(Timestamp, 1h)
| where ConnectionCount > 20 or BytesSent > 1000000
| extend
    BeaconPattern = iff(ConnectionCount > 50 and BytesSent < 10000, "Possible", "Unlikely"),
    DataTransferMB = round((BytesSent + BytesReceived) / 1024.0 / 1024.0, 2)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, ConnectionCount, DataTransferMB, BeaconPattern
| order by ConnectionCount desc""",
        {"timeframe": "7d"},
        "low",
        "Web traffic is ubiquitous. Focus on unusual processes or beacon-like patterns (high frequency, low data).",
        ["Network"]
    ),

    (
        "T1071.001",
        "sentinelone",
        """// MITRE ATT&CK T1071.001 - Web Protocols C2
EventType = "IP Connect" AND
DstPort In ("80", "443", "8080", "8443") AND
NOT SrcProcName In ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "Teams.exe")""",
        {},
        "low",
        "Common traffic pattern. Look for unusual processes or known malicious domains.",
        ["Network"]
    ),

    # T1090.002 - External Proxy
    (
        "T1090.002",
        "defender",
        """// MITRE ATT&CK T1090.002 - Proxy: External Proxy
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceNetworkEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where RemotePort in (1080, 3128, 8080, 8888, 9050)  // Common proxy ports
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    UniqueProxies = dcount(RemoteIP),
    ProxyIPs = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 1h)
| where ConnectionCount > 5
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName, ConnectionCount, UniqueProxies, ProxyIPs
| order by ConnectionCount desc""",
        {"timeframe": "7d"},
        "medium",
        "Proxy usage may be legitimate or for evasion. Validate against corporate proxy infrastructure.",
        ["Network"]
    ),
]


def get_phase3_templates():
    """Return the list of Phase 3 templates."""
    return PHASE3_TEMPLATES
