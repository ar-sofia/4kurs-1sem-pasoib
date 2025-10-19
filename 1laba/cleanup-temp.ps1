# Virus_INFECTED
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red
try {
    $InfectionMarker = "INFECTED"
    Set-Content -Path "$env:TEMP\virus_log.txt" -Value "File infected: cleanup-temp.ps1" -ErrorAction SilentlyContinue
} catch {
    # Ignore errors in infection marker
}

# Original file content:

Write-Host "=== CLEANUP TEMP FILES ===" -ForegroundColor Green

$tempPaths = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")
$totalSize = 0

foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        $files = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue
        $size = ($files | Measure-Object -Property Length -Sum).Sum / 1MB
        $totalSize += $size
        Write-Host "Found $($files.Count) files in $path ($([math]::Round($size, 2)) MB)" -ForegroundColor Yellow
    }
}

Write-Host "Total temp files size: $([math]::Round($totalSize, 2)) MB" -ForegroundColor Red
$confirm = Read-Host "Delete temporary files? (y/n)"
if ($confirm -eq 'y') {
    foreach ($path in $tempPaths) {
        Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
    }
    Write-Host "Temporary files deleted!" -ForegroundColor Green
}









