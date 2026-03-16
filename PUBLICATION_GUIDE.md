# Operation Epic Fury — Publication Guide
**Step-by-step for every platform. Follow in order.**
**Date target: 2026-03-17 (publication day)**

---

## CHECKLIST RAPIDA

| # | Piattaforma | Tipo | Priorità | Fatto |
|---|-------------|------|----------|-------|
| 1 | GitHub repo push | Regole + IOC | CRITICA | ☐ |
| 2 | YARAify | 3 regole YARA | ALTA | ☐ |
| 3 | ThreatFox API | 12 IOC | ALTA | ☐ |
| 4 | OTX AlienVault | Pulse completo | ALTA | ☐ |
| 5 | MalwareBazaar | 3 hash SHA256 | ALTA | ☐ |
| 6 | SigmaHQ PR | 5 regole Sigma | MEDIA | ☐ |
| 7 | awesome-yara PR | 3 regole YARA | MEDIA | ☐ |
| 8 | SOC Prime | 5 regole Sigma | MEDIA | ☐ |
| 9 | VirusTotal community | 4 post su campioni | MEDIA | ☐ |
| 10 | ANY.RUN / Triage | Analisi pubblica | BASSA | ☐ |

---

## 1. GITHUB — Push del repository

Il repository locale è già inizializzato con il primo commit.

### 1.1 Crea il repository su GitHub
1. Vai su https://github.com/new
2. **Repository name:** `operation-epic-fury-rules`
3. **Description:** `YARA + Sigma detection rules and IOCs for Operation Epic Fury — Iranian APT dual-platform campaign 2026`
4. Visibilità: **Public**
5. **NON** spuntare "Add README" (ce l'hai già)
6. Clicca **Create repository**

### 1.2 Collega e fai push
```bash
cd /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules

# Sostituisci con il tuo username GitHub
git remote add origin https://github.com/paolocostanzo/operation-epic-fury-rules.git

# Rinomina branch master → main (convenzione GitHub)
git branch -m master main

# Push
git push -u origin main
```

### 1.3 Dopo il push
- Aggiungi **Topics** (Settings → Topics): `yara`, `sigma`, `threat-intelligence`, `iran`, `apt`, `malware`, `ioc`, `android-spyware`, `operation-epic-fury`
- Aggiungi il link al repo nell'articolo del blog

---

## 2. YARAIFY — Upload YARA Rules

URL: https://yaraify.abuse.ch/

Devi caricare **3 regole separatamente**.

### Regola 1: IranianAPT_LotAccess_EXE_2026

1. Vai su https://yaraify.abuse.ch/yarahub/
2. Clicca **"Submit YARA rule"**
3. Incolla il contenuto di `yara/IranianAPT_LotAccess_EXE_2026.yar`
4. Campi:
   - **Rule name:** `IranianAPT_LotAccess_EXE_2026`
   - **TLP:** WHITE
   - **Description:** LotAccess trojanized AppEx VPN client — Operation Epic Fury (Iran/Israel 2026). Windows RAT with RDTSC anti-VM evasion. Secondary C2 167.160.187.43 had 0/94 VT at publication.
   - **Tags:** `iran`, `apt`, `lotaccess`, `windows`, `rdtsc`, `anti-vm`, `operation-epic-fury`
   - **Reference:** `https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/`
5. Submit

### Regola 2: IranianAPT_LotAccess_Family

1. Stessa procedura
2. Campi:
   - **Rule name:** `IranianAPT_LotAccess_Family`
   - **Description:** Medium-confidence family rule for trojanized AppEx VPN clients — detects future LotAccess variants. Fires on 3/5 shared strings.
   - **Tags:** `iran`, `apt`, `lotaccess`, `windows`, `appex-vpn`, `family-rule`
   - **Reference:** `https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/`

### Regola 3: IranianAPT_RedAlert_APK_2026

1. Stessa procedura
2. Campi:
   - **Rule name:** `IranianAPT_RedAlert_APK_2026`
   - **Description:** Detects RedAlert fake APK (com.red.alertx) and umgdn (com.net.alerts) — Iranian Android spyware targeting Israeli civilians. Covers stage 1 + stage 2 + Pushy.me C2 channel.
   - **Tags:** `iran`, `apt`, `android`, `spyware`, `redalert`, `pushy-me`, `operation-epic-fury`
   - **Reference:** `https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/`

---

## 3. THREATFOX — Submit IOCs via API

URL: https://threatfox.abuse.ch/

Hai bisogno di un account. La submission avviene via API.

### 3.1 Ottieni API key
1. Registrati su https://threatfox.abuse.ch/register/
2. Vai su https://threatfox.abuse.ch/api/ → copia la tua API key

### 3.2 Submit IP indicators (C2 servers)

```bash
# Sostituisci YOUR_API_KEY con la tua chiave

# Primary C2
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "botnet_cc",
    "ioc_type": "ip:port",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "LotAccess Windows RAT primary C2 — Operation Epic Fury — Iranian campaign Feb 2026. AppEx VPN API on port 443. RDTSC anti-VM active.",
    "tags": ["iran", "apt", "operation-epic-fury", "lotaccess", "rdtsc"],
    "iocs": ["216.45.58.148:443"]
  }'

# Secondary C2 (undisclosed — 0/94 VT)
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "botnet_cc",
    "ioc_type": "ip:port",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "LotAccess Windows RAT secondary C2 — 0/94 VirusTotal at publication. Found via JARM fingerprint pivot. Not documented in any prior vendor report. Operation Epic Fury.",
    "tags": ["iran", "apt", "operation-epic-fury", "lotaccess", "undisclosed"],
    "iocs": ["167.160.187.43:443"]
  }'
```

### 3.3 Submit domain indicators

```bash
# Primary C2 domain
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "botnet_cc",
    "ioc_type": "domain",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "Primary C2 domain for LotAccess Windows RAT and RedAlert Android spyware — Operation Epic Fury. Registered 2025-06-23 NameCheap.",
    "tags": ["iran", "apt", "operation-epic-fury"],
    "iocs": ["api.ra-backup.com"]
  }'

# Secondary C2 domain (0/94 VT)
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "botnet_cc",
    "ioc_type": "domain",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "Secondary C2 domain — 0/94 VirusTotal. Resolves to 167.160.187.43. Registered 2025-07-08 NameCheap. Operation Epic Fury.",
    "tags": ["iran", "apt", "operation-epic-fury", "undisclosed"],
    "iocs": ["9732.5486311.xyz"]
  }'
```

### 3.4 Submit hash indicators

```bash
# LotAccess v3
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "payload",
    "ioc_type": "sha256_hash",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "LotAccessUI.EXE v3 — trojanized AppEx Networks VPN 2016. 13/72 VT. CrowdStrike CLEAN. RDTSC anti-VM evasion. Mutex: tqvpn-gui-keep-one-instance. Operation Epic Fury.",
    "tags": ["iran", "apt", "lotaccess", "rdtsc", "operation-epic-fury"],
    "iocs": ["6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6"]
  }'

# LotAccess v1
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "payload",
    "ioc_type": "sha256_hash",
    "malware": "win.lotaccess",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "LotAccessUI.EXE v1 — first VT submission 2025-12-16 (10 weeks pre-operation). 4/65 VT. Operation Epic Fury.",
    "tags": ["iran", "apt", "lotaccess", "operation-epic-fury"],
    "iocs": ["7d43d7f6c743912b74273901494ed18451aa2824130d9d405da250a9fe3aad0d"]
  }'

# RedAlert APK
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "payload",
    "ioc_type": "sha256_hash",
    "malware": "apk.redalert_spyware",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "RedAlert fake APK — com.red.alertx — Iranian Android spyware targeting Israeli civilians. Exfiltrates SMS/GPS/contacts to api.ra-backup.com. Operation Epic Fury.",
    "tags": ["iran", "apt", "android", "redalert", "spyware", "operation-epic-fury"],
    "iocs": ["83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72"]
  }'

# umgdn APK (stage 2 — undisclosed)
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{
    "query": "submit_ioc",
    "auth_key": "YOUR_API_KEY",
    "threat_type": "payload",
    "ioc_type": "sha256_hash",
    "malware": "apk.redalert_spyware",
    "confidence_level": 90,
    "reference": "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/",
    "comment": "umgdn APK — com.net.alerts — stage 2 Android spyware. UNDISCLOSED — not in any prior vendor report. Pushy.me secondary C2 channel. Operation Epic Fury.",
    "tags": ["iran", "apt", "android", "redalert", "spyware", "pushy-me", "undisclosed", "operation-epic-fury"],
    "iocs": ["0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8"]
  }'
```

---

## 4. OTX ALIENVAULT — Crea Pulse

URL: https://otx.alienvault.com/

Ho già preparato il JSON completo: `otx_pulse.json`

### 4.1 Via Web UI (più semplice)

1. Vai su https://otx.alienvault.com/ → login
2. Clicca **"Create Pulse"** (in alto a destra)
3. Copia i campi da `otx_pulse.json`:
   - **Name:** `Operation Epic Fury — Iranian APT Dual-Platform Campaign (Android+Windows) 2026`
   - **Description:** copia il campo `description` dal JSON
   - **TLP:** WHITE
   - **Tags:** copia dal campo `tags` (iran, iranian-apt, operation-epic-fury, ecc.)
4. **Aggiungi gli indicatori** dalla sezione `indicators`:
   - Per ogni elemento: seleziona il tipo (IPv4 / hostname / URL / FileHash-SHA256 / FileHash-MD5), incolla il valore, incolla il `title` come description
5. Imposta **Public: Yes**
6. Submit

### 4.2 Via API (automatico)

```bash
# Ottieni API key da: https://otx.alienvault.com/api (sezione "Your API Keys")
OTX_API_KEY="YOUR_OTX_API_KEY_HERE"

curl -X POST https://otx.alienvault.com/api/v1/pulses/create \
  -H "X-OTX-API-KEY: $OTX_API_KEY" \
  -H "Content-Type: application/json" \
  -d @/home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/otx_pulse.json
```

Se il curl ritorna errore 400, usa la UI Web (step 4.1).

---

## 5. MALWAREBAZAAR — Upload Campioni

URL: https://bazaar.abuse.ch/

**NOTA: Devi avere i file binari (EXE e APK).** Non hai i file, hai solo gli hash.

### Se hai i file:

1. Vai su https://bazaar.abuse.ch/upload/
2. Per ogni campione:
   - Carica il file
   - **Tags:** `iran`, `apt`, `lotaccess`, `operation-epic-fury` (per l'EXE) oppure `iran`, `apt`, `android`, `redalert`, `operation-epic-fury` (per gli APK)
   - **Comment:** descrizione breve
   - **Reference:** `https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/`

### Se non hai i file:

Puoi segnalare gli hash noti tramite la community di MalwareBazaar:
- Vai su https://bazaar.abuse.ch/browse/ e cerca l'hash
- Se il campione esiste già, aggiungi un tag o commento tramite il bottone **"Add tag"**
- Hash da cercare:
  - `6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6` (LotAccess v3)
  - `83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72` (RedAlert APK)

---

## 6. SIGMAHQ — Pull Request

URL: https://github.com/SigmaHQ/sigma

Contribuisci 5 regole Sigma (escludi quella Android — va su un repo diverso).

### 6.1 Fork e setup

```bash
# 1. Forka https://github.com/SigmaHQ/sigma su GitHub (bottone "Fork")

# 2. Clona il fork
git clone https://github.com/paolocostanzo/sigma.git
cd sigma

# 3. Crea branch
git checkout -b feat/operation-epic-fury-iranian-apt-2026
```

### 6.2 Copia le regole nelle directory corrette

```bash
# Directory corrette per SigmaHQ:
# - Regole network Windows → rules/windows/network_connection/
# - Regole registry → rules/windows/registry/registry_set/
# - Regole process → rules/windows/process_creation/
# - Regole proxy → rules/proxy/

# C2 network (network_connection)
cp /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/sigma/iranian_apt_lotaccess_c2_network.yml \
   rules/windows/network_connection/net_connection_win_iranian_apt_lotaccess_c2.yml

# Payload extraction (process_creation - file creation)
cp /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/sigma/iranian_apt_lotaccess_payload_extraction.yml \
   rules/windows/process_creation/proc_creation_win_iranian_apt_lotaccess_payload_extraction.yml

# Registry C2 (registry_set)
cp /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/sigma/iranian_apt_lotaccess_registry_c2.yml \
   rules/windows/registry/registry_set/registry_set_iranian_apt_lotaccess_c2.yml

# Scheduled task (process_creation)
cp /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/sigma/iranian_apt_lotaccess_scheduled_task.yml \
   rules/windows/process_creation/proc_creation_win_iranian_apt_lotaccess_scheduled_task.yml

# WScript child (process_creation)
cp /home/brainonion/.openclaw/workspace-main/operation-epic-fury-rules/sigma/iranian_apt_lotaccess_wscript_child.yml \
   rules/windows/process_creation/proc_creation_win_iranian_apt_lotaccess_wscript_child.yml
```

### 6.3 Verifica con sigma-cli (opzionale ma raccomandato)

```bash
pip install sigma-cli
sigma check rules/windows/network_connection/net_connection_win_iranian_apt_lotaccess_c2.yml
```

### 6.4 Aggiungi `modified` e `version` a ogni regola

SigmaHQ richiede questi campi aggiuntivi. Aggiungi dopo `date:`:
```yaml
date: 2026/03/15
modified: 2026/03/17
version: 1
```

### 6.5 Commit e PR

```bash
git add rules/
git commit -m "Add Iranian APT Operation Epic Fury detection rules (LotAccess Windows RAT + C2)

5 Sigma rules for detecting Operation Epic Fury — Iranian-linked dual-platform
campaign (Android + Windows) targeting Israeli civilians, February 2026.

Covers: C2 network contact, payload extraction, registry C2 write,
scheduled task masquerade, WScript child process.

Reference: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/"

git push origin feat/operation-epic-fury-iranian-apt-2026
```

Poi vai su GitHub e apri la PR verso `SigmaHQ/sigma:master`.

**Titolo PR:** `Add Iranian APT Operation Epic Fury detection rules (LotAccess Windows RAT)`

**Corpo PR:**
```
## Summary

5 Sigma rules for Operation Epic Fury — original OSINT research published 2026-03-17.

Iranian-linked dual-platform campaign targeting Israeli civilians with fake RedAlert rocket alert app (February 28, 2026).

### Rules included

| File | Level | Category |
|------|-------|----------|
| `net_connection_win_iranian_apt_lotaccess_c2.yml` | CRITICAL | network_connection |
| `proc_creation_win_iranian_apt_lotaccess_payload_extraction.yml` | HIGH | process_creation |
| `registry_set_iranian_apt_lotaccess_c2.yml` | HIGH | registry_set |
| `proc_creation_win_iranian_apt_lotaccess_scheduled_task.yml` | HIGH | process_creation |
| `proc_creation_win_iranian_apt_lotaccess_wscript_child.yml` | MEDIUM | process_creation |

### Key IOCs detected

- C2 IPs: 216.45.58.148 (documented) + **167.160.187.43 (0/94 VT, undisclosed)**
- Mutex: `tqvpn-gui-keep-one-instance` (zero expected false positives)
- Scheduled task masquerade: `Microsoft-Windows-DiskDiagnosticDataCollector` pointing to %TEMP%
- RDTSC anti-VM active: C2 network rule fires only on physical hardware

### References

- Full research: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
- Detection rules repo: https://github.com/paolocostanzo/operation-epic-fury-rules
```

---

## 7. AWESOME-YARA — Pull Request

URL: https://github.com/InQuest/awesome-yara

### 7.1 Fork e setup

```bash
git clone https://github.com/paolocostanzo/awesome-yara.git
cd awesome-yara
git checkout -b add-operation-epic-fury-rules
```

### 7.2 Modifica README.md

Cerca la sezione **"Threat Intelligence"** o **"APT / Nation State"** (o simile) e aggiungi:

```markdown
* [IranianAPT_LotAccess_EXE_2026](https://github.com/paolocostanzo/operation-epic-fury-rules/blob/main/yara/IranianAPT_LotAccess_EXE_2026.yar) - High-confidence rule for LotAccessUI.EXE, trojanized AppEx VPN client used in Operation Epic Fury (Iranian APT, 2026). Detects via mutex, C2 IPs, and AppEx API strings. Includes undisclosed secondary C2 (0/94 VT).
* [IranianAPT_LotAccess_Family](https://github.com/paolocostanzo/operation-epic-fury-rules/blob/main/yara/IranianAPT_LotAccess_Family.yar) - Medium-confidence family rule for future AppEx VPN trojanized variants. Fires on 3/5 shared strings.
* [IranianAPT_RedAlert_APK_2026](https://github.com/paolocostanzo/operation-epic-fury-rules/blob/main/yara/IranianAPT_RedAlert_APK_2026.yar) - Detects RedAlert fake APK (com.red.alertx) + umgdn (com.net.alerts) — Iranian Android spyware targeting Israeli civilians.
```

### 7.3 Commit e PR

```bash
git add README.md
git commit -m "Add Operation Epic Fury YARA rules — Iranian APT dual-platform campaign 2026"
git push origin add-operation-epic-fury-rules
```

PR verso `InQuest/awesome-yara:master`.
**Titolo:** `Add Operation Epic Fury YARA rules (Iranian APT, LotAccess + RedAlert APK)`

---

## 8. SOC PRIME — Upload Sigma Rules

URL: https://socprime.com/

SOC Prime Threat Detection Marketplace accetta contribuzioni Sigma.

### 8.1 Registrazione e submission

1. Crea account su https://socprime.com/
2. Vai su **"Content"** → **"Submit Detection"** (o simile nella nav)
3. Per ogni regola Sigma:
   - Carica il file `.yml`
   - Compila i metadati richiesti
   - **Reference:** link al tuo articolo
   - Seleziona le piattaforme SIEM supportate (Splunk, QRadar, Elastic, ecc.)

**Regole da caricare (priorità):**
1. `iranian_apt_lotaccess_c2_network.yml` — CRITICAL
2. `iranian_apt_lotaccess_payload_extraction.yml` — HIGH
3. `iranian_apt_lotaccess_registry_c2.yml` — HIGH
4. `iranian_apt_lotaccess_scheduled_task.yml` — HIGH
5. `iranian_apt_lotaccess_wscript_child.yml` — MEDIUM

**Nota:** SOC Prime ha un processo di review, potrebbero passare alcuni giorni prima dell'approvazione.

---

## 9. VIRUSTOTAL — Community Posts sui Campioni

Devi fare post manuali su 4 pagine VT.

### Campione 1 — LotAccess v3 (SHA256)
URL: `https://www.virustotal.com/gui/file/6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6`

**Post:**
```
🚨 Operation Epic Fury — Iranian APT | Windows RAT with RDTSC anti-VM

This is LotAccessUI.EXE v3, a trojanized AppEx Networks VPN client (2016) used
in an Iranian-linked campaign targeting Israeli civilians following the Feb 28,
2026 military operation.

WHY MOST AV IS SILENT: Active RDTSC anti-VM evasion (T1497.003). The malware
measures CPU cycle counts to detect sandbox environments. If a VM is detected,
it NEVER contacts the C2. CrowdStrike Falcon classifies it CLEAN. 59/72 VT
vendors are silent. No public sandbox has ever captured C2 traffic in 4 years.

Key IOCs:
• Mutex: tqvpn-gui-keep-one-instance (zero false positives)
• Primary C2: 216.45.58.148 / api.ra-backup.com (HostPapa AS36352)
• Secondary C2: 167.160.187.43 / 9732.5486311.xyz — 0/94 VT (undisclosed)
• Registry: HKCU\Software\AppEx Networks\LotAccess\firstServer → C2 IP
• Persistence: schtasks masquerade as Microsoft-Windows-DiskDiagnosticDataCollector
• JARM: 21d14d00021d21d00042d43d43d00041dd0fae37a26d202d4ca73c3c7b57c5a55
  (shared by both C2s — JARM pivot led to discovery of secondary C2)

YARA + Sigma detection rules: https://github.com/paolocostanzo/operation-epic-fury-rules
Full research: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
```

### Campione 2 — LotAccess v1 (SHA256)
URL: `https://www.virustotal.com/gui/file/7d43d7f6c743912b74273901494ed18451aa2824130d9d405da250a9fe3aad0d`

**Post:**
```
🕵️ Operation Epic Fury — LotAccess v1 | First submission 2025-12-16 (10 weeks pre-operation)

This is the first known version of the LotAccess Windows RAT used in Operation
Epic Fury. First submitted to VirusTotal on December 16, 2025 — 10 weeks before
the February 28, 2026 operation. Proves infrastructure was prepared months in advance.

4/65 VT detections. RDTSC anti-VM evasion active.

Same campaign as SHA256:
6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6 (v3)

Detection rules: https://github.com/paolocostanzo/operation-epic-fury-rules
Research: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
```

### Campione 3 — RedAlert APK (SHA256)
URL: `https://www.virustotal.com/gui/file/83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72`

**Post:**
```
📱 Operation Epic Fury — RedAlert Fake APK | Iranian Android Spyware

Package: com.red.alertx
Stage 1 of a two-stage Android spyware operation targeting Israeli civilians.

Exfiltrates: SMS messages, GPS location, contact list
C2: http://api.ra-backup.com/analytics/submit.php (offline since ~2026-03-08)

Stage 2 APK (undisclosed, not in any prior report):
• Package: com.net.alerts (umgdn)
• SHA256: 0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8
• Uses Pushy.me as resilient secondary C2 channel (survives backend takedown)

Attribution: MuddyWater / MOIS (medium confidence, per Hunt.io infrastructure analysis)
Tactical convergence with Arid Viper 2023 TTP pattern.

YARA detection rule: https://github.com/paolocostanzo/operation-epic-fury-rules/blob/main/yara/IranianAPT_RedAlert_APK_2026.yar
Full research: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
```

### Campione 4 — umgdn APK (SHA256) — UNDISCLOSED
URL: `https://www.virustotal.com/gui/file/0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8`

**Post:**
```
🔍 Operation Epic Fury — umgdn APK (UNDISCLOSED) | Stage 2 Android Spyware + Pushy.me C2

Package: com.net.alerts
This second-stage Android spyware was NOT documented in any prior public report
(Unit 42, CloudSEK, Cloudforce One, ClearSky, Trellix, Sophos).

Key finding: uses Pushy.me (api.pushy.me/register) as a resilient secondary C2
channel. Push-based command delivery survives backend (api.ra-backup.com) takedown.

SHA256: 0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8

Stage 1 APK: com.red.alertx
SHA256: 83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72

YARA: https://github.com/paolocostanzo/operation-epic-fury-rules/blob/main/yara/IranianAPT_RedAlert_APK_2026.yar
Research: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
```

---

## 10. ANY.RUN / TRIAGE — Analisi Pubblica

### ANY.RUN
1. Vai su https://app.any.run/
2. Clicca **"New Task"**
3. Carica LotAccessUI.EXE (se hai il file)
4. **IMPORTANTE:** seleziona **"Physical machine"** se disponibile, oppure testa su Windows fisico — l'RDTSC anti-VM impedirà l'attivazione su VM
5. Imposta come **Public** e aggiungi tag: `iran`, `lotaccess`, `operation-epic-fury`
6. Se il campione viene eseguito su VM: l'analisi mostrerà attività limitata (niente C2) — questo è il comportamento ATTESO e dimostra l'evasione

### Triage (Hatching)
1. Vai su https://tria.ge/
2. Carica il campione
3. Aggiungi alla descrizione il link al tuo articolo
4. Imposta come Public

**Nota:** su entrambe le piattaforme l'RDTSC evasion impedirà C2 contact su VM. L'assenza di C2 traffic nelle analisi pubbliche è essa stessa un IOC significativo da menzionare.

---

## ORDINE DI ESECUZIONE CONSIGLIATO (il giorno della pubblicazione)

```
06:00  Push GitHub repo (step 1)
06:30  ThreatFox API (step 3) — automatico con curl
07:00  OTX AlienVault (step 4) — curl o web UI
07:30  YARAify (step 2) — 3 regole, ~15 min
08:00  VT community posts (step 9) — 4 post, ~20 min
09:00  PUBBLICA L'ARTICOLO sul blog
09:30  MalwareBazaar (step 5)
10:00  SigmaHQ PR (step 6)
11:00  awesome-yara PR (step 7)
12:00+ SOC Prime (step 8) — può aspettare
```

---

## NOTE FINALI

- **Embargo:** non pubblicare regole prima dell'articolo (protezione primacy)
- **Attribuzione:** se qualcuno usa le regole, non rimuovere il campo `author` nei metadata
- **Aggiornamenti:** se vengono trovati nuovi campioni o varianti, aggiorna l'IOC CSV e fai un nuovo commit nel repo GitHub
- **Secondary C2 status:** verificare se 167.160.187.43 e 9732.5486311.xyz sono ancora attivi prima della pubblicazione con `nmap -p 443 167.160.187.43`
