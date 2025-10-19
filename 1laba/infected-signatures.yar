rule Signatures_PS1 {
    strings:
        $sig1 = "Virus_INFECTED" ascii
        $sig2 = "Set-Content -Path" ascii
        $sig3 = "File infected:" ascii
        
    condition:
        2 of them
}