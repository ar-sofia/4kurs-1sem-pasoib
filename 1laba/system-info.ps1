# Virus_INFECTED
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red
try {
    $InfectionMarker = "INFECTED"
    Set-Content -Path "$env:TEMP\virus_log.txt" -Value "File infected: system-info.ps1" -ErrorAction SilentlyContinue
} catch {
    # Ignore errors in infection marker
}

# Original file content:

# Original file content:
Write-Host "=== SYSTEM INFORMATION ===" -ForegroundColor Green
$os = Get-WmiObject -Class Win32_OperatingSystem
$cpu = Get-WmiObject -Class Win32_Processor
$ram = [math]::Round($os.TotalVisibleMemorySize/1MB, 2)

Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor Cyan
Write-Host "CPU: $($cpu.Name)" -ForegroundColor Cyan
Write-Host "RAM: $ram GB" -ForegroundColor Cyan
Write-Host "Architecture: $($os.OSArchitecture)" -ForegroundColor Cyan
Write-Host "Uptime: $([math]::Round($os.SystemUpTime/3600, 1)) hours" -ForegroundColor Cyan







