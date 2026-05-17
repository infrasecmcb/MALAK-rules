# MALAK Rules — Detection Notes
**11 Suricata rules + 5 YARA rules** — AI-generated, validated on Suricata 8.0.4 / YARA 4.x, running in production.

## Suricata
| # | SID | CVE | Promoted | Description |
|---|-----|-----|----------|-------------|
| 1 | 1000909 | — | 2026-05-11 | CVE-TEST-2026-CLAUDE-001 TestCorp FleetManager Pre-Auth RCE via API token replay |
| 2 | 1000910 | — | 2026-05-13 | TI.HIGH.OAUTH.DeviceCodeRequestPlainHTTP.Storm2372 |
| 3 | 1000914 | — | 2026-05-13 | TI.MEDIUM.OAUTH.NonBrowserDeviceCodeUA.Storm2372 |
| 4 | 1000915 | — | 2026-05-11 | TI.HIGH.PHISH.OAuthRelayTyposquatDNS.Storm2372 |
| 5 | 1001031 | [CVE-2015-1642](https://nvd.nist.gov/vuln/detail/CVE-2015-1642) | 2026-05-09 | CVE-2015-1642 Microsoft Office Memory Corruption via Malicious RTF |
| 6 | 1001129 | [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638) | 2026-05-09 | CVE-2017-5638 Apache Struts2 OGNL RCE via Content-Type |
| 7 | 1001171 | [CVE-2020-8655](https://nvd.nist.gov/vuln/detail/CVE-2020-8655) | 2026-05-09 | CVE-2020-8655 EyesOfNetwork Privilege Escalation via API |
| 8 | 1001198 | [CVE-2019-4716](https://nvd.nist.gov/vuln/detail/CVE-2019-4716) | 2026-05-09 | CVE-2019-4716 IBM Planning Analytics Java Deserialization RCE |
| 9 | 1001321 | [CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) | 2026-05-09 | ET.HIGH.RCE.WPFileManager.1321 |
| 10 | 1001322 | [CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) | 2026-05-09 | ET.HIGH.RCE.WPFileManager.elFinder.1322 |
| 11 | 1001323 | [CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) | 2026-05-09 | ET.HIGH.MALWARE.WPFileManager.WebshellExec.1323 |

## YARA — ICS/OT malware (`yara/malak-ics.yar`)
| # | Rule | Family | Severity | MITRE | Reference |
|---|------|--------|----------|-------|-----------|
| 1 | MALAK_ICS_Industroyer_Backdoor | Industroyer / CrashOverride | critical | T0831 | [ICS-CERT](https://ics-cert.us-cert.gov/alerts/ICS-ALERT-18-191-01) |
| 2 | MALAK_ICS_Triton_TRITON | Triton / Trisis | critical | T0838 | [FireEye](https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html) |
| 3 | MALAK_ICS_GreyEnergy_Mini | GreyEnergy | high | T0862 | [Securelist](https://securelist.com/greyenergy/88127/) |
| 4 | MALAK_ICS_Havex_Backdoor | Havex | high | T0862 | [F-Secure](https://www.f-secure.com/documents/996508/1030745/whitepaper_havex.pdf) |
| 5 | MALAK_ICS_Generic_Suspicious | Generic ICS/SCADA strings | medium | T1204.002 | [MITRE TA0040](https://attack.mitre.org/tactics/TA0040/) |

## Detection Rationale

### #01 — SID 1000909
**Rule:** `CVE-TEST-2026-CLAUDE-001 TestCorp FleetManager Pre-Auth RCE via API token replay`  
**Promoted:** 2026-05-11  
**Detects:** inspects `flow:established,to_server`, `http.method`, matches `POST` / `/api/v2/jobs/exec`  

### #02 — SID 1000910
**Rule:** `TI.HIGH.OAUTH.DeviceCodeRequestPlainHTTP.Storm2372`  
**Promoted:** 2026-05-13  
**Detects:** inspects `flow:established,to_server`, `http.uri`, matches `/oauth2` / `devicecode`  

### #03 — SID 1000914
**Rule:** `TI.MEDIUM.OAUTH.NonBrowserDeviceCodeUA.Storm2372`  
**Promoted:** 2026-05-13  
**Detects:** inspects `flow:established,to_server`, `http.user_agent`, matches `microsoftonline`  

### #04 — SID 1000915
**Rule:** `TI.HIGH.PHISH.OAuthRelayTyposquatDNS.Storm2372`  
**Promoted:** 2026-05-11  
**Detects:** inspects `dns.query`  

### #05 — SID 1001031 / CVE-2015-1642
**Rule:** `CVE-2015-1642 Microsoft Office Memory Corruption via Malicious RTF`  
**Promoted:** 2026-05-09  
**Vulnerability:** Microsoft Office memory corruption via malicious RTF document — triggers on HTTP delivery of RTF-typed content.  
**Detects:** inspects `flow:to_server,established`, `http.request_body`, matches `Content-Type: application/msword` / `<rtf>`  

### #06 — SID 1001129 / CVE-2017-5638
**Rule:** `CVE-2017-5638 Apache Struts2 OGNL RCE via Content-Type`  
**Promoted:** 2026-05-09  
**Vulnerability:** Apache Struts2 Jakarta Multipart parser RCE — attacker sends a crafted Content-Type header containing an OGNL expression that gets executed server-side.  
**Detects:** inspects `flow:established,to_server`, `http.method`, matches `POST` / `Content-Type|3a 20|`  

### #07 — SID 1001171 / CVE-2020-8655
**Rule:** `CVE-2020-8655 EyesOfNetwork Privilege Escalation via API`  
**Promoted:** 2026-05-09  
**Vulnerability:** EyesOfNetwork 5.3 privilege escalation — apache user can run arbitrary commands as root via a crafted NSE script for nmap through misconfigured sudoers.  
**Detects:** inspects `flow:established,to_server`, `http.method`, matches `POST` / `/eonweb/api/set_user_pref.php`  

### #08 — SID 1001198 / CVE-2019-4716
**Rule:** `CVE-2019-4716 IBM Planning Analytics Java Deserialization RCE`  
**Promoted:** 2026-05-09  
**Vulnerability:** IBM Planning Analytics 2.0.x config overwrite — unauthenticated user can login as admin then execute code as root via TM1 scripting (Java deserialization, magic bytes AC ED 00 05).  
**Detects:** inspects `flow:established,to_server`, `http.request_body`, matches `|AC ED 00 05|`  

### #09 — SID 1001321 / CVE-2020-25213
**Rule:** `ET.HIGH.RCE.WPFileManager.1321`  
**Promoted:** 2026-05-09  
**Vulnerability:** WordPress File Manager plugin <6.9 — renames an unsafe elFinder connector PHP file allowing unauthenticated remote code execution via file upload.  
**Detects:** inspects `flow:established,to_server`, `http.method`, matches `POST`  

### #10 — SID 1001322 / CVE-2020-25213
**Rule:** `ET.HIGH.RCE.WPFileManager.elFinder.1322`  
**Promoted:** 2026-05-09  
**Vulnerability:** Same WP File Manager flaw as #09 — pinpoints the exact `connector.minimal.php` exploit path used by mass scanners. Catches the upload command in the request body.  
**Detects:** inspects `flow:established,to_server`, `http.uri` `/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php`, `http.request_body` `cmd=upload`  

### #11 — SID 1001323 / CVE-2020-25213
**Rule:** `ET.HIGH.MALWARE.WPFileManager.WebshellExec.1323`  
**Promoted:** 2026-05-09  
**Vulnerability:** Post-exploitation companion to #10 — detects GET access to any PHP file dropped under `lib/files/`, the directory attackers use as a webshell staging area after a successful upload.  
**Detects:** inspects `flow:established,to_server`, `http.method` `GET`, `http.uri` `/wp-content/plugins/wp-file-manager/lib/files/` + `.php`  

## YARA Detection Notes

### `MALAK_ICS_Industroyer_Backdoor`
Detects Industroyer/CrashOverride — the malware used in the December 2016 Ukraine power grid attack. Matches PE binaries under 500KB carrying the strings `Crash`, `Override`, or `101.dll`, or a combination of `CreateFileA` + `WriteFile` with a valid MZ header. Reference: ICS-ALERT-18-191-01.

### `MALAK_ICS_Triton_TRITON`
Detects Triton/Trisis — the framework that targeted Schneider Electric Triconex safety controllers at a Saudi petrochemical plant in 2017. Matches PE binaries containing two of `TRITON`, `trilog.exe`, `libdc.so`, or any of `inject.bin` / `imain.bin`.

### `MALAK_ICS_GreyEnergy_Mini`
Detects the lightweight reconnaissance component of GreyEnergy, the successor to BlackEnergy seen in Eastern European energy sector campaigns. Matches PEs under 300KB with `GreyEnergy` strings or named pipe `\.\pipe\greyenergy`, or a combination of service-manipulation API calls.

### `MALAK_ICS_Havex_Backdoor`
Detects Havex — a backdoor that performed OPC server enumeration against energy-sector OT networks (Dragonfly/Energetic Bear campaign). Matches PE binaries with `Havex`, `opc.exe`, or `101.dll`, or OPC-related strings (`OPC Servers`, `CLSID`).

### `MALAK_ICS_Generic_Suspicious`
Catch-all for unknown binaries referencing multiple OT protocol stacks — `modbus`, `dnp3`, `iec 60870-5-104`, `opc ua`, `scada`, `plc program`, `wincc`, or `simatic`. Requires 3 distinct hits, PE header, and filesize < 2MB to limit false positives on legitimate engineering software.
