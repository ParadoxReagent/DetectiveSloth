"""Initial query templates for common MITRE ATT&CK techniques."""

# Template format: (technique_id, platform, query_template, variables, confidence, false_positive_notes, data_sources)

INITIAL_TEMPLATES = [
    # T1055 - Process Injection (Defender)
    (
        "T1055",
        "defender",
        """// MITRE ATT&CK T1055 - Process Injection Detection
// Confidence: {{ confidence | default('High') }}
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetWindowsHookEx", "NtMapViewOfSection"
)
or InitiatingProcessFileName in~ (
    "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"
)
| where not(FileName in~ ("known_legitimate_tool.exe"))  // Add your exceptions
{% if hashes %}
| where SHA256 in ({% for hash in hashes %}"{{ hash }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| summarize
    InjectionCount = count(),
    UniqueTargets = dcount(FileName),
    Commands = make_set(ProcessCommandLine, 5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where InjectionCount > 2
| project Timestamp, DeviceName, Injector = InitiatingProcessFileName, InjectionCount, UniqueTargets, SampleCommands = Commands
| order by Timestamp desc""",
        {"confidence": "High", "timeframe": "7d"},
        "high",
        "May trigger on legitimate debugging tools or security software. Review parent process chain.",
        ["Process", "Command Line"]
    ),

    # T1003 - Credential Dumping (Defender)
    (
        "T1003",
        "defender",
        """// MITRE ATT&CK T1003 - OS Credential Dumping
// Confidence: High
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where ProcessCommandLine has_any (
    "lsass", "procdump", "mimikatz", "sekurlsa",
    "comsvcs.dll", "MiniDump", "ntdsutil"
)
or (FileName =~ "rundll32.exe" and ProcessCommandLine contains "comsvcs.dll")
or (ProcessCommandLine contains "ntds.dit")
| where not(InitiatingProcessFileName in~ ("werfault.exe"))  // Exclude crash dumps
{% if hashes %}
| where SHA256 in ({% for hash in hashes %}"{{ hash }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| extend SuspicionLevel = case(
    ProcessCommandLine contains "mimikatz", "Critical",
    ProcessCommandLine contains "lsass" and ProcessCommandLine contains "dump", "High",
    ProcessCommandLine contains "ntds.dit", "Critical",
    "Medium"
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, SuspicionLevel
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "high",
        "Legitimate admin tools may trigger this. Validate with user and correlate with change tickets.",
        ["Process", "Command Line", "File"]
    ),

    # T1059.001 - PowerShell Execution (Defender)
    (
        "T1059.001",
        "defender",
        """// MITRE ATT&CK T1059.001 - PowerShell Malicious Execution
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-enc", "-encodedcommand", "-w hidden",
    "downloadstring", "downloadfile", "iex", "invoke-expression",
    "bitstransfer", "start-bitstransfer", "net.webclient"
)
{% if ips %}
| where ProcessCommandLine has_any ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
{% if domains %}
or ProcessCommandLine has_any ({% for domain in domains %}"{{ domain }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| extend SuspicionIndicators = pack_array(
    iff(ProcessCommandLine contains "-enc", "Encoded", ""),
    iff(ProcessCommandLine contains "-w hidden", "Hidden", ""),
    iff(ProcessCommandLine contains "downloadstring", "Download", ""),
    iff(ProcessCommandLine contains "iex", "Invoke", "")
)
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, SuspicionIndicators
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "PowerShell is widely used. Focus on encoded commands and download activity from unknown sources.",
        ["Process", "Command Line"]
    ),

    # T1055 - Process Injection (CrowdStrike)
    (
        "T1055",
        "crowdstrike",
        """// MITRE ATT&CK T1055 - Process Injection
#event_simpleName=ProcessRollup2
| (ImageFileName=/powershell\\.exe|rundll32\\.exe|regsvr32\\.exe/i
   AND CommandLine=/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC/i)
| groupBy([ComputerName, ImageFileName, CommandLine], function=[count(as=Events), collect([TargetProcessId])])
| Events > 1""",
        {},
        "high",
        "May trigger on legitimate tools. Correlate with parent process and network activity.",
        ["Process"]
    ),

    # T1003 - Credential Dumping (CrowdStrike)
    (
        "T1003",
        "crowdstrike",
        """// MITRE ATT&CK T1003 - Credential Dumping
#event_simpleName=ProcessRollup2
| CommandLine=/lsass|procdump|mimikatz|sekurlsa|comsvcs\\.dll|ntds\\.dit/i
| groupBy([ComputerName, CommandLine, UserName], function=[count(as=Events), min(ProcessStartTime)])
| sort(Events, order=desc)""",
        {},
        "high",
        "Validate against authorized administrative activity and change management records.",
        ["Process"]
    ),

    # T1059.001 - PowerShell (Carbon Black)
    (
        "T1059.001",
        "carbonblack",
        """// MITRE ATT&CK T1059.001 - PowerShell Execution
process_name:powershell.exe AND (
  process_cmdline:"-enc" OR
  process_cmdline:"-encodedcommand" OR
  process_cmdline:"downloadstring" OR
  process_cmdline:"iex" OR
  process_cmdline:"-w hidden"
)
AND NOT parent_name:"explorer.exe\"""",
        {},
        "medium",
        "Common in enterprise environments. Focus on encoded commands and unusual parent processes.",
        ["Process"]
    ),

    # T1053 - Scheduled Task (Defender)
    (
        "T1053",
        "defender",
        """// MITRE ATT&CK T1053 - Scheduled Task/Job
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceProcessEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where FileName in~ ("schtasks.exe", "at.exe")
    or ProcessCommandLine has_any ("New-ScheduledTask", "Register-ScheduledTask")
| where ProcessCommandLine has "/create" or ProcessCommandLine has "Register-ScheduledTask"
| where not(InitiatingProcessFileName in~ ("setup.exe", "msiexec.exe"))  // Exclude installers
| extend TaskName = extract(@'/tn\\s+"?([^"\\s]+)"?', 1, ProcessCommandLine)
| extend TaskAction = extract(@'/tr\\s+"?([^"]+)"?', 1, ProcessCommandLine)
| project Timestamp, DeviceName, InitiatingProcessFileName, TaskName, TaskAction, ProcessCommandLine
| order by Timestamp desc""",
        {"timeframe": "7d"},
        "medium",
        "Scheduled tasks are common in Windows. Focus on tasks created by unusual processes.",
        ["Process", "Command Line"]
    ),

    # T1021.001 - RDP (Defender)
    (
        "T1021.001",
        "defender",
        """// MITRE ATT&CK T1021.001 - Remote Desktop Protocol
// Confidence: Medium
// Timeframe: {{ timeframe | default('7d') }}

DeviceLogonEvents
| where Timestamp > ago({{ timeframe | default('7d') }})
| where LogonType == "RemoteInteractive"
| where not(AccountName endswith "$")  // Exclude machine accounts
{% if ips %}
| where RemoteIP in ({% for ip in ips %}"{{ ip }}"{{ ", " if not loop.last else "" }}{% endfor %})
{% endif %}
| summarize
    LogonCount = count(),
    FailedLogons = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    FirstLogon = min(Timestamp),
    LastLogon = max(Timestamp)
    by DeviceName, AccountName, RemoteIP
| where SuccessfulLogons > 0
| extend SuspicionScore = case(
    FailedLogons > 5 and SuccessfulLogons > 0, "High",
    LogonCount > 10, "Medium",
    "Low"
)
| project DeviceName, AccountName, RemoteIP, LogonCount, FailedLogons, SuccessfulLogons, FirstLogon, LastLogon, SuspicionScore
| order by SuspicionScore desc, LogonCount desc""",
        {"timeframe": "7d"},
        "medium",
        "RDP is commonly used. Focus on unusual source IPs, off-hours access, and failed attempts.",
        ["Logon"]
    ),

    # T1053 - Scheduled Task (SentinelOne)
    (
        "T1053",
        "sentinelone",
        """// MITRE ATT&CK T1053 - Scheduled Task Creation
EventType = "Process Creation" AND
(
  SrcProcCmdLine ContainsCIS "schtasks /create" OR
  SrcProcCmdLine ContainsCIS "at.exe" OR
  SrcProcCmdLine ContainsCIS "New-ScheduledTask" OR
  SrcProcCmdLine ContainsCIS "Register-ScheduledTask"
)
AND NOT SrcProcName In ("setup.exe", "msiexec.exe")""",
        {},
        "medium",
        "Common administrative activity. Investigate tasks with unusual actions or triggers.",
        ["Process"]
    ),
]


def get_initial_templates():
    """Return the list of initial templates."""
    return INITIAL_TEMPLATES
