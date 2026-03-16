/*
    Rule: IranianAPT_RedAlert_APK_2026
    Author: Paolo Costanzo - https://paolocostanzo.github.io
    Date: 2026-03-15
    TLP: WHITE
    License: MIT

    Description:
        Detects the fake "RedAlert" Android spyware family used in Operation Epic Fury
        (Iranian-linked campaign, February 28, 2026). Covers:
          - Stage 1: com.red.alertx (fake RedAlert app — smishing delivery)
          - Stage 2: com.net.alerts / umgdn (undisclosed second APK, not in any public report)

        The stage 2 APK (umgdn) uses Pushy.me as a resilient C2 push channel that
        survives backend takedown. Compiled within 24h of C2 domain registration.

        At least 6-7 variants distributed; condition uses shared strings across family.

    Samples:
        RedAlert APK (stage 1): 83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72
        umgdn APK (stage 2):    0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8

    MITRE ATT&CK (Mobile):
        T1437  Standard Application Layer Protocol (C2)
        T1430  Location Tracking
        T1636.002  Protected User Data: SMS Messages
        T1516  Input Injection (Pushy.me push channel)

    Reference: https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/
*/

rule IranianAPT_RedAlert_APK_2026 {
    meta:
        description     = "RedAlert fake APK spyware family - Operation Epic Fury (Iran/Israel 2026)"
        author          = "Paolo Costanzo - paolocostanzo.github.io"
        date            = "2026-03-15"
        tlp             = "WHITE"
        reference       = "https://paolocostanzo.github.io/operation-epic-fury-cyber-war-iran/"
        hash_redalert   = "83651b0589665b112687f0858bfe2832ca317ba75e700c91ac34025ee6578b72"
        hash_umgdn      = "0cba66e78ddaeecfdd462c8cb39e443d083dc58c609b0edc73e8101e59ca91e8"
        mitre_attack    = "T1437, T1430, T1636.002"
        confidence      = "HIGH"

    strings:
        // Package names — stage 1 and stage 2
        $pkg_stage1     = "com.red.alertx" ascii
        $pkg_stage2     = "com.net.alerts" ascii

        // Primary C2 endpoint
        $c2_host        = "api.ra-backup.com" ascii
        $c2_path        = "/analytics/submit.php" ascii

        // Pushy.me secondary C2 channel (survives backend takedown)
        $pushy_sdk      = "me.pushy.sdk" ascii
        $pushy_api      = "api.pushy.me" ascii

        // Stage 1 specific — installer spoofing and surveillance payload
        $spoof_store    = "com.android.vending" ascii    // spoof Google Play installer
        $dex_debug      = "DebugProbesKt.dex" ascii      // surveillance DEX stage 1

    condition:
        uint32(0) == 0x04034b50                          // PK magic — ZIP/APK
        and (
            ($pkg_stage1 and $c2_host)                   // stage 1 confirmed variant
            or ($pkg_stage2 and $c2_host)                // stage 2 (umgdn) confirmed
            or ($c2_path and ($pushy_sdk or $pushy_api)) // any variant with C2 + Pushy
        )
}
