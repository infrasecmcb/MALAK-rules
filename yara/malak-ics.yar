/*
 * MALAK ICS YARA Rules — malak-ics.yar
 * Targets ICS/OT malware families known to attack energy sector infrastructure.
 *
 * Rule IDs are stable — do not renumber. Add new rules below the last entry.
 */

rule MALAK_ICS_Industroyer_Backdoor {
    meta:
        description = "Detects Industroyer/CrashOverride backdoor targeting ICS"
        author = "MALAK"
        date = "2026-05-17"
        reference = "https://ics-cert.us-cert.gov/alerts/ICS-ALERT-18-191-01"
        mitre_technique = "T0831"
        severity = "critical"
        family = "Industroyer"

    strings:
        $a1 = "Crash" ascii wide
        $a2 = "Override" ascii wide
        $a3 = "101.dll" ascii wide
        $b1 = { 4D 5A }
        $c1 = "CreateFileA" ascii
        $c2 = "WriteFile" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 500KB
        and (1 of ($a*) or (all of ($c*) and $b1))
}

rule MALAK_ICS_Triton_TRITON {
    meta:
        description = "Detects Triton/Trisis malware targeting Schneider Electric SIS controllers"
        author = "MALAK"
        date = "2026-05-17"
        reference = "https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html"
        mitre_technique = "T0838"
        severity = "critical"
        family = "Triton"

    strings:
        $a1 = "TRITON" ascii wide nocase
        $a2 = "trilog.exe" ascii wide
        $a3 = "libdc.so" ascii wide
        $b1 = "inject.bin" ascii wide
        $b2 = "imain.bin" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (2 of ($a*) or 1 of ($b*))
}

rule MALAK_ICS_GreyEnergy_Mini {
    meta:
        description = "Detects GreyEnergy mini component used in ICS reconnaissance"
        author = "MALAK"
        date = "2026-05-17"
        reference = "https://securelist.com/greyenergy/88127/"
        mitre_technique = "T0862"
        severity = "high"
        family = "GreyEnergy"

    strings:
        $a1 = "GreyEnergy" ascii wide nocase
        $a2 = "\\.\\pipe\\greyenergy" ascii wide
        $b1 = "CreateServiceA" ascii
        $b2 = "OpenSCManagerA" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 300KB
        and (1 of ($a*) or all of ($b*))
}

rule MALAK_ICS_Havex_Backdoor {
    meta:
        description = "Detects Havex ICS backdoor used against energy sector OPC servers"
        author = "MALAK"
        date = "2026-05-17"
        reference = "https://www.f-secure.com/documents/996508/1030745/whitepaper_havex.pdf"
        mitre_technique = "T0862"
        severity = "high"
        family = "Havex"

    strings:
        $a1 = "Havex" ascii wide nocase
        $a2 = "101.dll" ascii wide
        $a3 = "opc.exe" ascii wide
        $b1 = "OPC Servers" ascii wide
        $b2 = "CLSID" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (1 of ($a*) or all of ($b*))
}

rule MALAK_ICS_Generic_Suspicious {
    meta:
        description = "Generic ICS suspicious file — references multiple OT protocol stacks"
        author = "MALAK"
        date = "2026-05-17"
        reference = "https://attack.mitre.org/tactics/TA0040/"
        mitre_technique = "T1204.002"
        severity = "medium"
        family = "ICS_Generic"

    strings:
        $modbus  = "modbus"    ascii wide nocase
        $dnp3    = "dnp3"      ascii wide nocase
        $iec104  = "iec 60870-5-104" ascii wide nocase
        $opcua   = "opc ua"    ascii wide nocase
        $scada   = "scada"     ascii wide nocase
        $plc     = "plc program" ascii wide nocase
        $hmi     = "wincc"     ascii wide nocase
        $siemens = "simatic"   ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and 3 of them
}
