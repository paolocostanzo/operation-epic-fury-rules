/*
    Rule: IranianAPT_LotAccess_Family
    Author: Paolo Costanzo - https://paolocostanzo.github.io
    Date: 2026-03-15
    TLP: WHITE
    License: MIT

    Description:
        Low-specificity family rule for AppEx Networks VPN clients trojanized
        with non-AppEx C2 infrastructure. Catches future variants with different
        C2 IPs but same architecture (mutex + cloudvpn.cfg + AppEx API).

        Three variants identified so far:
          v1 - first VT submission 2025-12-16 (10 weeks pre-operation, 4/65 detections)
          v2 - loaded 2026-03-08 (6/72 detections)
          v3 - loaded 2026-03-08 (13/72 detections) - main campaign sample

        Note: AppEx Networks VPN software is a legitimate Chinese enterprise VPN
        client from 2016. The legitimate binary is NOT malicious. This rule targets
        trojanized copies where C2 IPs have been injected.

        Confidence: MEDIUM — potential false positives on legitimate AppEx VPN installs
        (extremely rare: software is from 2016 and effectively defunct)

    Reference: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
*/

rule IranianAPT_LotAccess_Family {
    meta:
        description     = "AppEx Networks VPN client trojanized family — any C2 (Operation Epic Fury variants)"
        author          = "Paolo Costanzo - paolocostanzo.github.io"
        date            = "2026-03-15"
        tlp             = "WHITE"
        reference       = "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/"
        confidence      = "MEDIUM — possible false positives on legitimate AppEx VPN installs"
        mitre_attack    = "T1071.001, T1497.003, T1053.005, T1036.007, T1112"

    strings:
        $mutex          = "tqvpn-gui-keep-one-instance" ascii wide
        $cfg            = "cloudvpn.cfg" ascii wide
        $appex_api      = "/cgi-bin/d_device_action.py" ascii wide
        $sched_task     = "Microsoft-Windows-DiskDiagnosticDataCollector" ascii wide
        $reg_key        = "AppEx Networks\\LotAccess" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 3 of them      // 3/5 threshold — balance between FP rate and coverage
}
