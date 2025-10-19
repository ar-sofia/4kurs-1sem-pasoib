Write-Host "DETECTION OF VIRUS IN INFECTED FILES" -ForegroundColor Magenta

function Test-InfectedSignatures {
    param($filePath)
    
    $content = Get-Content $filePath -Raw
    $signatures = @()
    if ($content -match "Virus_INFECTED") {
        $signatures += "SIG1: Virus_INFECTED marker found"
    }
    if ($content -match "Set-Content -Path") {
        $signatures += "SIG3: Set-Content logging found"
    }
    if ($content -match "File infected:") {
        $signatures += "SIG5: File infection logging found"
    }
    return $signatures
}

Write-Host "`nScanning PowerShell files for virus signatures in infected files..." -ForegroundColor Yellow

Get-ChildItem -Filter "*.ps1" | Where-Object { $_.Name -ne "virus-prototype.ps1" } | ForEach-Object {
    Write-Host "`nChecking: $($_.Name)" -ForegroundColor Cyan
    
    $signatures = Test-InfectedSignatures $_.FullName
    
    if ($signatures.Count -gt 0) {
        Write-Host "🚨 VIRUS DETECTED IN INFECTED FILE! Found $($signatures.Count) signatures:" -ForegroundColor Red
        $signatures | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor Red
        }
        
        if ($signatures.Count -ge 3) {
            Write-Host "  Threat Level: HIGH (Multiple virus signatures)" -ForegroundColor Red
        } elseif ($signatures.Count -ge 2) {
            Write-Host "  Threat Level: MEDIUM (Virus signatures detected)" -ForegroundColor Yellow
        } else {
            Write-Host "  Threat Level: LOW (Single virus signature)" -ForegroundColor Green
        }
    } else {
        Write-Host "File appears clean" -ForegroundColor Green
    }
}

Write-Host "`nVIRUS SIGNATURES IN INFECTED FILES" -ForegroundColor Magenta
Write-Host "Signature 1: Virus_INFECTED - Virus marker in infected files" -ForegroundColor White
Write-Host "Signature 2: Set-Content -Path- File writing/logging" -ForegroundColor White
Write-Host "Signature 3: File infected- Infection logging" -ForegroundColor White