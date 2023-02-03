# Analynk

A URL analysis tool written in Go that uses threat intelligence platforms to analyse URLs. Previously analysed URLS are recognised and the analysis results are fetched.

```
usage: analynk --jbx-key=JBX-KEY --vt-key=VT-KEY [<flags>] <command> [<args> ...]

URL analyser application

Flags:
  --help             Show context-sensitive help (also try --help-long
                     and --help-man).
  --jbx-key=JBX-KEY  API key for joesecurity
  --vt-key=VT-KEY    API key for VirusTotal

Commands:
  help [<command>...]
    Show help.


  analyse --url=URL
    Analyse URL on VT and JoeSecurity threat intelligence platforms

    -u, --url=URL  URL to analyse on VT / Jbxcloud

  check-results --url=URL
    View results of a recent analysis

    -u, --url=URL  Analysed URL to view results for
```
