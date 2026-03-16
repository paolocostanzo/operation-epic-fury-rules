# Operation Epic Fury — Detection Rules & IOCs

**Author:** Paolo Costanzo — [paolocostanzo.github.io](https://paolocostanzo.github.io)
**Date:** 2026-03-15
**TLP:** WHITE — freely shareable
**License:** MIT

> Full technical research: [paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/](https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/)

---

## About This Research

Original OSINT investigation into **Operation Epic Fury** — an Iranian-linked dual-platform campaign (Android + Windows) that targeted Israeli civilians with a fake "RedAlert" rocket alert app following the military operation of February 28, 2026.

All findings in this repository were **not present in any prior public report** (Unit 42, CloudSEK, Cloudflare Cloudforce One, ClearSky, Trellix, Sophos) at time of publication.

Key original findings:

| # | Finding | Status in prior reports |
|---|---------|------------------------|
| 1 | Secondary Windows C2 (167.160.187.43 / 9732.5486311.xyz) — **0/94 VT** | ❌ Not documented |
| 2 | Windows payload: LotAccessUI.EXE (trojanized AppEx VPN 2016) | ❌ Not documented |
| 3 | Infrastructure active since **June 2025** (8 months pre-operation) | ❌ Not documented |
| 4 | Both C2 servers still active **17+ days post-operation** | ❌ Not documented |
| 5 | Second Android APK: umgdn / com.net.alerts with Pushy.me C2 | ❌ Not documented |
| 6 | Tactical convergence with Arid Viper 2023 (same TTP pattern) | ❌ Not documented |

### Why was the Windows payload invisible?

LotAccess implements **RDTSC anti-VM evasion** (T1497.003): it measures CPU cycle counts to detect sandbox environments. If a VM is detected, it never contacts the C2. Result: no public sandbox has ever captured C2 traffic from this sample in four years. CrowdStrike Falcon classifies it **CLEAN**. 59/72 VirusTotal vendors are silent.

---

## Repository Structure

```
operation-epic-fury-rules/
├── yara/
│   ├── IranianAPT_LotAccess_EXE_2026.yar      # High-confidence — specific campaign
│   ├── IranianAPT_LotAccess_Family.yar         # Medium-confidence — future variants
│   └── IranianAPT_RedAlert_APK_2026.yar        # Android APK family
├── sigma/
│   ├── iranian_apt_lotaccess_c2_network.yml           # CRITICAL — network C2 contact
│   ├── iranian_apt_lotaccess_payload_extraction.yml   # HIGH — %TEMP%\EB93A6\ creation
│   ├── iranian_apt_lotaccess_registry_c2.yml          # HIGH — registry C2 write
│   ├── iranian_apt_lotaccess_scheduled_task.yml       # HIGH — schtask masquerade
│   ├── iranian_apt_lotaccess_wscript_child.yml        # MEDIUM — WScript child process
│   └── iranian_apt_redalert_android_c2.yml            # CRITICAL — Android exfiltration
└── ioc/
    └── iocs.csv                                # Machine-readable IOC list
```

---

## YARA Rules

| Rule | Confidence | Target | Key Indicator |
|------|-----------|--------|---------------|
| `IranianAPT_LotAccess_EXE_2026` | HIGH | LotAccess v1/v2/v3 | mutex + C2 IP / AppEx API strings |
| `IranianAPT_LotAccess_Family` | MEDIUM | Any AppEx VPN trojanized | 3/5 shared strings |
| `IranianAPT_RedAlert_APK_2026` | HIGH | RedAlert APK + umgdn | package + C2 + Pushy.me |

> **Note on `IranianAPT_LotAccess_EXE_2026`:** The mutex `tqvpn-gui-keep-one-instance` alone is the strongest single indicator — zero expected false positives.

---

## Sigma Rules

| Rule | Level | Deployment | Note |
|------|-------|-----------|------|
| `iranian_apt_lotaccess_c2_network` | CRITICAL | Firewall / EDR / SIEM | Fires ONLY on physical hardware (RDTSC anti-VM) |
| `iranian_apt_lotaccess_payload_extraction` | HIGH | EDR | Earliest indicator — fires before C2 contact |
| `iranian_apt_lotaccess_registry_c2` | HIGH | EDR | Fires on physical HW; sandbox values = "123456" |
| `iranian_apt_lotaccess_scheduled_task` | HIGH | EDR / SIEM | Read filter notes — legitimate task exists |
| `iranian_apt_lotaccess_wscript_child` | MEDIUM | SIEM | Experimental — verify before production |
| `iranian_apt_redalert_android_c2` | CRITICAL | Proxy / NDR | Android exfiltration endpoint |

### Deployment priority

1. `iranian_apt_lotaccess_c2_network` + `iranian_apt_redalert_android_c2` — zero FP, deploy immediately
2. `IranianAPT_LotAccess_EXE_2026` YARA — endpoint scan and mail gateway
3. `iranian_apt_lotaccess_payload_extraction` — EDR, earliest warning
4. `iranian_apt_lotaccess_registry_c2` — EDR post-execution
5. `iranian_apt_lotaccess_scheduled_task` — read filter notes before deploying
6. `iranian_apt_lotaccess_wscript_child` — SIEM, review for FPs first

### Critical limitation

**RDTSC anti-VM is active.** The Windows C2 is never contacted in any sandbox environment. Rules `iranian_apt_lotaccess_c2_network` and `iranian_apt_lotaccess_registry_c2` (with real IPs) fire only on physical hardware. Filesystem and process rules (Sigma 2, 4, 5) work in VM environments.

---

## IOCs

See [`ioc/iocs.csv`](ioc/iocs.csv) for the full machine-readable list.

**Key indicators:**

| Type | Value | Note |
|------|-------|------|
| IP | `216.45.58.148` | Primary Windows C2 — HostPapa AS36352 |
| IP | `167.160.187.43` | Secondary Windows C2 — **0/94 VT** |
| Domain | `api.ra-backup.com` | Primary C2 domain |
| Domain | `9732.5486311.xyz` | Secondary C2 domain — **0/94 VT** |
| SHA256 | `6209a952...` | LotAccessUI.EXE v3 |
| SHA256 | `0cba66e7...` | umgdn APK (undisclosed) |
| Mutex | `tqvpn-gui-keep-one-instance` | Zero false positives |
| JARM | `21d14d00021d21d00042d43d...` | Shared by both C2s — pivot fingerprint |

---

## Related Public Reports (what they covered)

| Source | Date | Android | Windows | Secondary C2 |
|--------|------|:-------:|:-------:|:------------:|
| CloudSEK | 2026-03-03 | ✓ | ✗ | ✗ |
| Unit 42 (Palo Alto) | 2026-03-04 | ✓ | ✗ | ✗ |
| Cloudflare Cloudforce One | 2026-03-04 | ✓ | ✗ | ✗ |
| ClearSky / Trellix / Sophos | Mar 2026 | ✓ | ✗ | ✗ |

---

## MITRE ATT&CK Coverage

| Technique | Tactic | Description |
|-----------|--------|-------------|
| T1497.003 | Defense Evasion | RDTSC Time-Based Evasion — sandbox bypass |
| T1071.001 | Command & Control | AppEx VPN API as C2 protocol |
| T1112 | Defense Evasion | Registry modification (C2 config) |
| T1053.005 | Persistence | Scheduled Task (masquerade) |
| T1036.007 | Defense Evasion | Masquerade Task Name |
| T1059.007 | Execution | JavaScript via WScript.exe |
| T1583.001 | Resource Development | Acquire Infrastructure: Domains |

---

## License

MIT — Use freely, attribution appreciated.
If you find these rules useful or detect new variants, reach out: me@paolocostanzo.com

---

*Research conducted using public tools only: VirusTotal (free tier), FOFA, crt.sh, nmap, openssl.*
*No privileged access. All findings reproducible.*
