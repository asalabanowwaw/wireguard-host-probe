$ErrorActionPreference = 'Stop'
$taskTools = Join-Path $env:LOCALAPPDATA 'WireGuardNetworkTuner\tools'
New-Item -ItemType Directory -Path $taskTools -Force | Out-Null
$taskRelease = Invoke-RestMethod -Uri 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'
$taskAsset = $taskRelease.assets | Where-Object name -eq 'Xray-windows-64.zip'
if (-not $taskAsset) { throw 'Official Windows x64 Xray asset was not found.' }
$taskArchive = Join-Path $taskTools 'xray.zip'
Invoke-WebRequest -UseBasicParsing -Uri $taskAsset.browser_download_url -OutFile $taskArchive -TimeoutSec 120
if ($taskAsset.digest -and $taskAsset.digest.StartsWith('sha256:')) {
    $taskHash = (Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($taskHash -ne $taskAsset.digest.Substring(7)) { throw 'Official asset SHA256 did not match. Aborting.' }
}
Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskTools -Force
Remove-Item -LiteralPath $taskArchive
Write-Output "Official Xray $($taskRelease.tag_name) installed."
Write-Output 'Run Start local tuner.cmd, then open http://127.0.0.1:8788.'
