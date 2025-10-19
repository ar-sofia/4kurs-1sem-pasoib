# Virus_INFECTED
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red
try {
    $InfectionMarker = "INFECTED"
    Set-Content -Path "$env:TEMP\virus_log.txt" -Value "File infected: disk-monitor.ps1" -ErrorAction SilentlyContinue
} catch {
    # Ignore errors in infection marker
}

# Original file content:


# Original file content:
# ������ ��� ����������� ��������� ������������
Write-Host "=== ���������� ������ ===" -ForegroundColor Green

Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {
    $freeSpace = [math]::Round($_.FreeSpace / 1GB, 2)
    $totalSpace = [math]::Round($_.Size / 1GB, 2)
    $usedPercent = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)
    
    $color = if ($usedPercent -gt 90) { "Red" } elseif ($usedPercent -gt 75) { "Yellow" } else { "Green" }
    
    Write-Host "$($_.DeviceID) - $freeSpace GB �������� �� $totalSpace GB ($usedPercent% ������)" -ForegroundColor $color
}

Write-Host "`n����������� �������: >90%, ��������������: >75%" -ForegroundColor Gray






