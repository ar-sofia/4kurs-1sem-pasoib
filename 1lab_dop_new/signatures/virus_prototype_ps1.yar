/*
 * YARA signature for virus.prototype.ps1 detection
 * Based on injected_signatures.yar rule
 */

rule virus_prototype_ps1 {
    meta:
        description = "Detects virus.prototype.ps1 malware in PowerShell scripts"
        author = "Security Team"
        version = "1.0"
        date = "2025-10-16"
        hash = "not_available"
        reference = "internal_analysis"
        severity = "high"
        category = "trojan"
        
    strings:
        $sig1 = "Virus_INFECTED" ascii
        $sig2 = "Set-Content -Path" ascii
        $sig3 = "File infected:" ascii
        
    condition:
        all of them
}
