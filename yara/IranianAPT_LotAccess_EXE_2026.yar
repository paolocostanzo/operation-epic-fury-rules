/*
    Rule: IranianAPT_LotAccess_EXE_2026
    Author: Paolo Costanzo - https://paolocostanzo.github.io
    Date: 2026-03-15
    TLP: WHITE
    License: MIT

    Description:
        Detects LotAccessUI.EXE, a trojanized version of AppEx Networks VPN client (2016),
        used in Operation Epic Fury — an Iranian-linked campaign targeting Israeli civilians
        with a fake "RedAlert" rocket alert app (February 28, 2026).

        This payload was completely unknown to all public threat intel vendors at time of
        publication. CrowdStrike Falcon classifies it CLEAN. 59/72 VirusTotal vendors
        are silent. No public sandbox has ever captured C2 traffic due to RDTSC anti-VM
        evasion (T1497.003).

        Reference: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/

    Samples:
        SHA256 v3: 6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6
        SHA256 v1: 7d43d7f6c743912b74273901494ed18451aa2824130d9d405da250a9fe3aad0d
        MD5:       58dad3a41691265128c751d133d5525f
        Imphash:   d89625bf08b621847b3ab97338a84dda

    MITRE ATT&CK:
        T1071.001  Application Layer Protocol (C2 via AppEx VPN API)
        T1497.003  Time Based Evasion - RDTSC anti-VM
        T1053.005  Scheduled Task/Job (persistence, masquerading as Windows task)
        T1036.007  Masquerade Task or Service
        T1112      Modify Registry (C2 config written to HKCU AppEx keys)
        T1059.007  JavaScript (file "152" / download.js via WScript.exe)
*/

rule IranianAPT_LotAccess_EXE_2026 {
    meta:
        description     = "LotAccess trojanized AppEx VPN client - Operation Epic Fury (Iran/Israel 2026)"
        author          = "Paolo Costanzo - paolocostanzo.github.io"
        date            = "2026-03-15"
        reference       = "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/"
        hash_v3_sha256  = "6209a9524e97ee8ac5fb05668f2be9a18a455870bb8cf6022049ee8f458c12d6"
        hash_v1_sha256  = "7d43d7f6c743912b74273901494ed18451aa2824130d9d405da250a9fe3aad0d"
        pe_imphash      = "d89625bf08b621847b3ab97338a84dda"
        mitre_attack    = "T1071.001, T1497.003, T1053.005, T1036.007, T1112, T1059.007"
        confidence      = "HIGH"
        yarahub_uuid              = "30d13fd1-fbc1-446a-9e1d-853a2dd55d4b"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_reference_md5     = "58dad3a41691265128c751d133d5525f"

    strings:
        // Mutex — unique to this campaign, zero expected false positives
        $mutex          = "tqvpn-gui-keep-one-instance" ascii wide

        // Primary C2 IP (documented by Unit 42, CloudSEK)
        $c2_ip_primary  = "216.45.58.148" ascii wide

        // Secondary C2 IP (0/94 VT — undisclosed, found via JARM pivot)
        $c2_ip_backup   = "167.160.187.43" ascii wide

        // Primary C2 hostname
        $c2_host        = "api.ra-backup.com" ascii wide

        // Runtime-written VPN config file containing C2 IPs
        $cfg            = "cloudvpn.cfg" ascii wide

        // AppEx VPN API protocol strings — C2 traffic mimics legitimate VPN
        $appex_api_1    = "/cgi-bin/d_device_action.py?ButtonDownSSLFile" ascii wide
        $appex_api_2    = "/cgi-bin/d_device_action.py?ButtonSSLClientDownLinked" ascii wide

        // AppEx Networks identity strings
        $appex_brand    = "AppEx Networks" ascii wide
        $tianqin        = "TianQin" ascii wide

        // Scheduled task name used for persistence (masquerades as Windows built-in)
        $sched_task     = "Microsoft-Windows-DiskDiagnosticDataCollector" ascii wide

        // Registry key path where C2 IPs are written at runtime
        $reg_key        = "AppEx Networks\\LotAccess" ascii wide

    condition:
        uint16(0) == 0x5A4D                             // MZ header — PE file
        and filesize < 5MB
        and (
            $mutex                                       // strongest: campaign-unique mutex
            or ($c2_ip_primary and $cfg)                 // primary C2 IP + VPN config
            or ($c2_ip_backup and $cfg)                  // undisclosed secondary C2 + config
            or ($c2_host and $cfg)                       // C2 hostname + VPN config
            or (($appex_api_1 or $appex_api_2) and ($c2_ip_primary or $c2_ip_backup or $c2_host))
            or ($reg_key and $sched_task and ($appex_brand or $tianqin))  // registry + persistence + AppEx identity
        )
}
