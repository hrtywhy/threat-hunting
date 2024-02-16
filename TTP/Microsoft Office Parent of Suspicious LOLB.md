## Emulation & Validation

```
The easiest and most straightforward method to validate would be to run a Word or Excel document containing a macro that would then launch one of the executables identified in the query.

Atomic Red Team Validation: 
T1204.002 Atomic

NOTE: You can change the "macro_choice" option to 1 for cmd.exe, 2 for powershell.exe, 3 for wmic.exe and 4 for schtasks.exe

Invoke-AtomicTest T1204.002 -TestName "Office Product Spawning Suspicious LOLB" -PathToAtomicsFolder C:\AtomicRedTeam\ -InputArgs @{"macro_choice" = "1"}
```
## Query Logic

| Selection	| Field | Value |
|-----------|-------|-------|   
| parent_process (ANY)		  | parent_process_path	| *EXCEL.EXE
|         	|       | *WINWORD.EXE
|         	|       | *POWERPNT.exe
|         	|       | *MSPUB.exe
|         	|       | *VISIO.exe
|         	|       | *OUTLOOK.EXE
|         	|       | *ONENOTE.EXE
| process (ANY)	| process_path	| *schtasks.exe
|           |	      | *cscript.exe
|           |	      | *cmd.exe
|           |	      | *powershell.exe
|           |	      | *wscript.exe
|           |	      | *scrcons.exe
|           |	      | *hh.exe
|           |	      | *wmic.exe
|           |	      | *mshta.exe
|           |	      | *rundll32.exe
|           |	      | *msiexec.exe
|           |	      | *forfiles.exe
|           |	      | *scriptrunner.exe
|           |	      | *svchost.exe
|           |	      | *control.exe
|           |	      | *msdt.exe
|           |	      | *certutil.exe




## Hunt Queries

- Carbon Black

```
((parent_name:EXCEL.EXE OR parent_name:WINWORD.EXE OR parent_name:POWERPNT.exe OR parent_name:MSPUB.exe OR parent_name:VISIO.exe OR parent_name:OUTLOOK.EXE OR parent_name:ONENOTE.EXE) AND (process_name:msdt.exe OR process_name:schtasks.exe OR process_name:cscript.exe OR process_name:cmd.exe OR process_name:powershell.exe OR process_name:wscript.exe OR process_name:scrcons.exe OR process_name:regsvr32.exe OR process_name:hh.exe OR process_name:wmic.exe OR process_name:mshta.exe OR process_name:rundll32.exe OR process_name:msiexec.exe OR process_name:forfiles.exe OR process_name:scriptrunner.exe OR process_name:svchost.exe OR process_name:control.exe OR process_name:certutil.exe))
```
- Crowdstrike
```
TERM(EXE) (ParentBaseFileName IN ("EXCEL.EXE", "WINWORD.EXE", "POWERPNT.exe", "MSPUB.exe", "VISIO.exe", "OUTLOOK.EXE", "*ONENOTE.EXE") AND (FileName IN ("msdt.exe", "schtasks.exe", "cscript.exe", "cmd.exe", "powershell.exe", "wscript.exe", "scrcons.exe", "regsvr32.exe", "hh.exe", "wmic.exe", "mshta.exe", "rundll32.exe", "msiexec.exe", "forfiles.exe", "scriptrunner.exe", "svchost.exe", "control.exe", "certutil.exe")))
| stats values(_time) as eventTimes, values(GrandParentBaseFileName) as grandParentProcessNames, values(ParentBaseFileName) as ParentProcesses, values(CommandLine) as commandLines, values(ContextProcessId_decimal) as contextProcessDecimal count by ComputerName, ImageFileName
| convert ctime(eventTimes)
```
- Elastic
```
{
  "bool": {
    "must": [
      {
        "bool": {
          "should": [
            {
              "query_string": {
                "query": "/.*[Ee][Xx][Cc][Ee][Ll]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ww][Ii][Nn][Ww][Oo][Rr][Dd]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Pp][Oo][Ww][Ee][Rr][Pp][Nn][Tt]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Mm][Ss][Pp][Uu][Bb]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Vv][Ii][Ss][Ii][Oo]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Oo][Uu][Tt][Ll][Oo][Oo][Kk]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Oo][Nn][Ee][Nn][Oo][Tt][Ee]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "parent_process_path",
                  "process.parent.executable"
                ]
              }
            }
          ]
        }
      },
      {
        "bool": {
          "should": [
            {
              "query_string": {
                "query": "/.*[Ss][Cc][Hh][Tt][Aa][Ss][Kk][Ss]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Cc][Ss][Cc][Rr][Ii][Pp][Tt]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Cc][Mm][Dd]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ww][Ss][Cc][Rr][Ii][Pp][Tt]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ss][Cc][Rr][Cc][Oo][Nn][Ss]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Rr][Ee][Gg][Ss][Vv][Rr]32\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Hh][Hh]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ww][Mm][Ii][Cc]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Mm][Ss][Hh][Tt][Aa]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Rr][Uu][Nn][Dd][Ll][Ll]32\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Mm][Ss][Ii][Ee][Xx][Ee][Cc]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ff][Oo][Rr][Ff][Ii][Ll][Ee][Ss]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ss][Cc][Rr][Ii][Pp][Tt][Rr][Uu][Nn][Nn][Ee][Rr]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Ss][Vv][Cc][Hh][Oo][Ss][Tt]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Cc][Oo][Nn][Tt][Rr][Oo][Ll]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Cc][Ee][Rr][Tt][Uu][Tt][Ii][Ll]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            },
            {
              "query_string": {
                "query": "/.*[Mm][Ss][Dd][Tt]\\.[Ee][Xx][Ee]/",
                "fields": [
                  "process_path",
                  "process.executable"
                ]
              }
            }
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
| where InitiatingProcessFileName has_any (
  "EXCEL.exe",
  "WINWORD.exe",
  "POWERPNT.exe",
  "MSPUB.exe",
  "VISIO.exe",
  "OUTLOOK.exe",
  "ONENOTE.EXE"
)
| where FileName has_any (
  "msdt.exe",
  "schtasks.exe",
  "cscript.exe",
  "cmd.exe",
  "powershell.exe",
  "wscript.exe",
  "scrcons.exe",
  "regsvr32.exe",
  "hh.exe",
  "wmic.exe",
  "mshta.exe",
  "rundll32.exe",
  "msiexec.exe",
  "forfiles.exe",
  "scriptrunner.exe",
  "svchost.exe",
  "control.exe"
  "certutil.exe"
)
| project Timestamp, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256, ReportId, DeviceId
| order by Timestamp
```

- Microsoft Sentinel
```
SecurityEvent
| where ParentProcessName has_any (
  "EXCEL",
  "WINWORD",
  "POWERPNT",
  "MSPUB",
  "VISIO",
  "OUTLOOK",
  "ONENOTE.EXE"
)
| where NewProcessName has_any (
  "msdt.exe",
  "schtasks.exe",
  "cscript.exe",
  "cmd.exe",
  "powershell.exe",
  "wscript.exe",
  "scrcons.exe",
  "regsvr32.exe",
  "hh.exe",
  "wmic.exe",
  "mshta.exe",
  "rundll32.exe",
  "msiexec.exe",
  "forfiles.exe",
  "scriptrunner.exe",
  "svchost.exe",
  "control.exe"
  "certutil.exe"
)
| project TimeGenerated, Computer, tostring(EventID), ParentProcessName, NewProcessName, CommandLine, SubjectUserName, SourceComputerId, processID=tolong(NewProcessId), parentProcessID=tolong(ProcessId), EventData| order by TimeGenerated
```
- Cortex XDR
```
dataset = xdr_data
| fields agent_hostname, action_process_image_name, action_process_image_path, action_process_os_pid, action_process_image_command_line, action_process_image_extension, os_actor_process_image_path, action_process_requested_parent_pid, causality_actor_process_os_pid, causality_actor_process_image_name, causality_actor_primary_username
| filter action_process_image_path in ("*schtasks.exe","*cscript.exe","*cmd.exe","*powershell.exe","*wscript.exe","*scrcons.exe","*regsvr32.exe","*hh.exe","*wmic.exe","*mshta.exe","*rundll32.exe","*msiexec.exe","*forfiles.exe","*scriptrunner.exe","*svchost.exe","*control.exe","*msdt.exe","*certutil.exe")
| filter os_actor_process_image_path in ("*EXCEL.EXE","*WINWORD.EXE","*POWERPNT.exe","*MSPUB.exe","*VISIO.exe","*OUTLOOK.EXE","*ONENOTE.EXE")
| comp min(_time) as firstSeen, max(_time) as lastSeen, values(action_process_image_command_line) as process_Cmdline, values(action_process_image_name) as process, values(action_process_image_path) as process_Path, values(action_process_os_pid) as process_Id, values(os_actor_process_image_path) as parent_Process, values(action_process_requested_parent_pid) as parent_Process_Id, values(causality_actor_process_image_name) as grandparent_Process, values(causality_actor_process_os_pid) as grandparent_Process_Id, values(causality_actor_primary_username) as username, count_distinct(action_process_image_command_line) as commandCnt by agent_hostname
| fields agent_hostname, firstSeen, lastSeen, process_Cmdline, process, process_Path, process_Id, parent_Process, parent_Process_Id, grandparent_Process, grandparent_Process_Id, username, commandCnt
```
- QRadar
```
SELECT DATEFORMAT(starttime,'YYYY-MM-dd H:mm') AS startTime, QIDDESCRIPTION(qid) AS eventName, "Machine ID" AS sourceHost, "Parent Process Path" AS parentProcessPath, "Process Path" AS processPath, "Process CommandLine" AS processCmdline, UTF8(payload) as searchPayload
FROM events 
WHERE ((parentProcessPath ILIKE '%EXCEL.EXE' OR parentProcessPath ILIKE '%WINWORD.EXE' OR parentProcessPath ILIKE '%POWERPNT.exe' OR parentProcessPath ILIKE '%MSPUB.exe' OR parentProcessPath ILIKE '%VISIO.exe' OR parentProcessPath ILIKE '%OUTLOOK.EXE' OR parentProcessPath ILIKE '%ONENOTE.EXE') AND (processPath ILIKE '%msdt.exe' OR processPath ILIKE '%schtasks.exe' OR processPath ILIKE '%cscript.exe' OR processPath ILIKE '%cmd.exe' OR processPath ILIKE '%powershell.exe' OR processPath ILIKE '%wscript.exe' OR processPath ILIKE '%scrcons.exe' OR processPath ILIKE '%regsvr32.exe' OR processPath ILIKE '%hh.exe' OR processPath ILIKE '%wmic.exe' OR processPath ILIKE '%mshta.exe' OR processPath ILIKE '%rundll32.exe' OR processPath ILIKE '%msiexec.exe' OR processPath ILIKE '%forfiles.exe' OR processPath ILIKE '%scriptrunner.exe' OR processPath ILIKE '%svchost.exe' OR processPath ILIKE '%control.exe' OR processPath ILIKE '%certutil.exe'))
LAST 24 HOURS
```
- SentinelOne
```
EventType = "Process Creation" AND (SrcProcParentImagePath EndsWith AnyCase "EXCEL.EXE" OR SrcProcParentImagePath EndsWith AnyCase "MSPUB.exe" OR SrcProcParentImagePath EndsWith AnyCase "ONENOTE.EXE" OR SrcProcParentImagePath EndsWith AnyCase "OUTLOOK.EXE" OR SrcProcParentImagePath EndsWith AnyCase "POWERPNT.exe" OR SrcProcParentImagePath EndsWith AnyCase "VISIO.exe" OR SrcProcParentImagePath EndsWith AnyCase "WINWORD.EXE") AND (SrcProcImagePath EndsWith AnyCase "certutil.exe" OR SrcProcImagePath EndsWith AnyCase "cmd.exe" OR SrcProcImagePath EndsWith AnyCase "control.exe" OR SrcProcImagePath EndsWith AnyCase "cscript.exe" OR SrcProcImagePath EndsWith AnyCase "forfiles.exe" OR SrcProcImagePath EndsWith AnyCase "hh.exe" OR SrcProcImagePath EndsWith AnyCase "msdt.exe" OR SrcProcImagePath EndsWith AnyCase "mshta.exe" OR SrcProcImagePath EndsWith AnyCase "msiexec.exe" OR SrcProcImagePath EndsWith AnyCase "powershell.exe" OR SrcProcImagePath EndsWith AnyCase "regsvr32.exe" OR SrcProcImagePath EndsWith AnyCase "rundll32.exe" OR SrcProcImagePath EndsWith AnyCase "schtasks.exe" OR SrcProcImagePath EndsWith AnyCase "scrcons.exe" OR SrcProcImagePath EndsWith AnyCase "scriptrunner.exe" OR SrcProcImagePath EndsWith AnyCase "svchost.exe" OR SrcProcImagePath EndsWith AnyCase "wmic.exe" OR SrcProcImagePath EndsWith AnyCase "wscript.exe")
```

- Splunk
```
index=* sourcetype=* (parent_process_path IN ("*EXCEL.EXE","*WINWORD.EXE","*POWERPNT.exe","*MSPUB.exe","*VISIO.exe","*OUTLOOK.EXE","*ONENOTE.EXE") AND (process_path IN ("*\\msdt.exe", "*\\schtasks.exe","*\\cscript.exe","*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\scrcons.exe","*\\regsvr32.exe","*\\hh.exe","*\\wmic.exe","*\\mshta.exe","*\\rundll32.exe","*\\msiexec.exe","*\\forfiles.exe","*\\scriptrunner.exe","*\\svchost.exe","*\\control.exe","*\\certutil.exe")))
| rename hostname AS SourceHost, parent_process_path as ParentProcess, process_path as Process, username AS SourceUsername
| stats values(_time) as Occurences, values(SourceUsername) AS SourceUsernames, values(process_cmdline) AS CommandLines,  count by SourceHost, ParentProcess, Process
| convert ctime(Occurences)
| sort -count
```

- Trend Micro Vision One
```
eventSubId:2 AND ((parentFilePath:(EXCEL.EXE OR WINWORD.EXE OR POWERPNT.exe OR MSPUB.exe OR VISIO.exe OR OUTLOOK.EXE OR ONENOTE.EXE) AND processFilePath:(schtasks.exe OR cscript.exe OR cmd.exe OR powershell.exe OR wscript.exe OR scrcons.exe OR regsvr32.exe OR hh.exe OR wmic.exe OR mshta.exe OR rundll32.exe OR msiexec.exe OR forfiles.exe OR scriptrunner.exe OR svchost.exe OR control.exe OR msdt.exe OR certutil.exe)) OR (processFilePath:(EXCEL.EXE OR WINWORD.EXE OR POWERPNT.exe OR MSPUB.exe OR VISIO.exe OR OUTLOOK.EXE OR ONENOTE.EXE) AND objectFilePath:(schtasks.exe OR cscript.exe OR cmd.exe OR powershell.exe OR wscript.exe OR scrcons.exe OR regsvr32.exe OR hh.exe OR wmic.exe OR mshta.exe OR rundll32.exe OR msiexec.exe OR forfiles.exe OR scriptrunner.exe OR svchost.exe OR control.exe OR msdt.exe OR certutil.exe)))
```

## References
1. https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/ 
2. https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
3. https://twitter.com/Unit42_Intel/status/1620531956504055812
4. https://twitter.com/ffforward/status/1621195397250289664
5. https://www.proofpoint.com/uk/blog/threat-insight/bumblebee-buzzes-back-black
6. https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/trojanized-onenote-document-leads-to-formbook-malware/



