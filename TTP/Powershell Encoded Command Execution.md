## Emulation & Validation

```
The most direct method to generate applicable telemetry for the Hunt Package is to execute the Atomic Test below or run the manual command provided on a Windows cmd.exe prompt. The manual test command runs an "echo Hello!" command in PowerShell.

powershell.exe -en^co ZQBjAGgAbwAgACIASABlAGwAbABvACEAIgA=


Atomic Red Team Validation: 
T1027 Atomic

Invoke-AtomicTest T1027 -TestNames "Execute base64-encoded PowerShell", "Execute base64-encoded PowerShell from Windows Registry"
```
## Query Logic

| Selection	| Field | Value |
|-----------|-------|-------|   
|process	| process_path	| *powershell.exe
|commandline_re	| process_cmdline	| .*\-[Ee^]{1,2}[NnCcOoDdEeMmAa^`]+\s+\"?[a-zA-Z0-9+\/=]{6,}.*

## Hunt Queries

- Crowdstrike

```TERM("powershell") event_simpleName IN ("ProcessRollup2", "SyntheticProcessRollup2") FileName="powershell.exe" event_platform="Win"
| regex CommandLine="\-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+\s+\"?[a-zA-Z0-9+\/=]{6,}"
| stats values(_time) as eventTimes, count as eventCount, values(GrandParentBaseFileName) as grandParentProcessNames, values(ParentBaseFileName) as parentProcessNames, values(TargetProcessId_decimal) as processIds, values(CommandLine) as commandLines by ComputerName, ImageFileName
| convert ctime(eventTimes)
| sort eventCount asc
```
- Elastic
```
{  
  "bool": {
    "must": [
      {
        "query_string": {
          "query": "/.*-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+ +\\\"?[a-zA-Z0-9+\\/=]{6,}.*/",
          "fields": [
            "process_cmdline"
          ]
        }
      },
      {
        "query_string": {
          "query": "/.*powershell.exe/",
          "fields": [
            "process_path"
          ]
        }
      }
    ]
  }
}
```
- Microsoft Defender
```
DeviceProcessEvents
| project DeviceId, DeviceName, ActionType, Timestamp, FolderPath, FileName, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex "-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+\\s+\"?[a-zA-Z0-9+/=]{6,}"
```
- Cortex XDR
```
dataset = xdr_data
| filter action_process_image_name = "powershell.exe"
| filter action_process_image_command_line ~= "\-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+\s+\"?[a-zA-Z0-9+\/=]{6,}"
| fields event_type as eventType, event_sub_type as eventSubType, agent_hostname as sourceHost, causality_actor_process_image_path as causalityProcessPath, os_actor_process_image_path as parentProcessPath, action_process_image_path as processPath, action_process_cwd as processCurrentWorkingDirectory, causality_actor_process_command_line as causalityProcessCommandLine, os_actor_process_command_line as parentProcessCommandLine, action_process_image_command_line as processCommandLine, causality_actor_process_os_pid as causalityProcessId, action_process_requested_parent_pid as parentProcessId, action_process_os_pid as processId, causality_actor_primary_username as causalityUserName, action_process_username as processUserName, actor_causality_id as causalityId, action_process_device_info as processDeviceInfo, causality_actor_process_image_sha256 as causalityProcessSHA256, os_actor_process_image_sha256 as parentProcessSHA256, action_process_image_sha256 as processSHA256, causality_actor_process_signature_product as causalityProcessProductName, os_actor_process_signature_product as parentProcessProductName, action_process_signature_product as processProductName, causality_actor_process_signature_vendor as causalityProcessVendorName, os_actor_process_signature_vendor  as parentProcessVendorName, action_process_signature_vendor as processVendorName, causality_actor_process_signature_status as causalitySignatureStatus, os_actor_process_signature_status as parentProcessSignatureStatus, action_process_signature_status as processSignatureStatus, action_process_integrity_level as processIntegrityLevel, causality_actor_process_file_original_name as causalityOriginalName, causality_actor_process_file_internal_name as causalityInternalFileName, os_actor_process_file_original_name as parentOriginalName, os_actor_process_file_internal_name as parentInternalFileName
```

- Sentinel One
```
(SrcProcCmdLine RegExp "..*\-[Ee^]{1,2}[NnCcOoDdEeMmAa^`]+\s+\"?[a-zA-Z0-9+\/=]{6,}..*" AND SrcProcImagePath EndsWith AnyCase "powershell.exe")
```
- Splunk
```
index=* sourcetype=* process_path="*\\powershell.exe" 
| regex process_cmdline="\-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+\s+\"?[a-zA-Z0-9+\/=]{6,}"
| rename process_cmdline AS "processCmdline", process_path AS "processPath", parent_process_path AS "parentProcessPath",  hostname AS "sourceHost"
| stats values(_time) as occurrences, values(processCmdline) as ProcessCommands, values(parentProcessPath) as ParentProcesses, values(processPath) as Processes count by sourceHost
| convert ctime(occurrences) 
| table occurrences, sourceHost, ProcessCommands, ParentProcesses, Processes
```
- Carbon Black
```
(process_name:powershell.exe AND cmdline:-e*) AND -cmdline:-noninter*
```
- Microsoft Sentinel
```
SecurityEvent
| where TimeGenerated >= ago(7d)
| project TimeGenerated, Computer, Activity, EventID, CommandLine, NewProcessName, processId = tolong(NewProcessId), ParentProcessName, parentProcessId = tolong(ProcessId)
| where NewProcessName endswith "powershell.exe"
| where CommandLine matches regex "-[Ee^]{1,2}[NnCcOoDdEeMmAaPpHh^`]+\\s+\"?[a-zA-Z0-9+/=]{6,}"
```
## References
1. https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/
2. https://cycraft.com/download/CyCraft-Whitepaper-Chimera_V4.1.pdf

