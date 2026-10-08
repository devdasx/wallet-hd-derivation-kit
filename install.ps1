param(
  [string]$Version = "1.0.1",
  [string]$Prefix = "$HOME\AppData\Local\wallethd",
  [switch]$Force,
  [switch]$DryRun,
  [switch]$NoVerify,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$destination = Join-Path $Prefix "wallethd.exe"
if ($Uninstall) {
  if ($DryRun) { Write-Host "Would remove $destination"; exit 0 }
  Remove-Item -Force -ErrorAction SilentlyContinue $destination
  Write-Host "Removed $destination"
  exit 0
}
if (-not [Environment]::Is64BitOperatingSystem) { throw "Windows x86-64 is required" }
$artifact = "wallethd-v$Version-windows-x86_64.zip"
$release = "https://github.com/devdasx/wallet-hd-derivation-kit/releases/download/v$Version"
if ($DryRun) { Write-Host "Would download $release/$artifact and install to $destination"; exit 0 }
if ((Test-Path $destination) -and -not $Force) { throw "$destination exists; pass -Force to replace it" }
$temp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  Invoke-WebRequest -UseBasicParsing "$release/$artifact" -OutFile "$temp\$artifact"
  if (-not $NoVerify) {
    Invoke-WebRequest -UseBasicParsing "$release/SHA256SUMS" -OutFile "$temp\SHA256SUMS"
    $line = Get-Content "$temp\SHA256SUMS" | Where-Object { $_ -match [regex]::Escape($artifact) }
    if (-not $line) { throw "Artifact is absent from SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash "$temp\$artifact" -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum verification failed" }
  }
  Expand-Archive "$temp\$artifact" -DestinationPath $temp -Force
  New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
  Copy-Item -Force "$temp\wallethd.exe" $destination
  & $destination version
  Write-Host "Installed $destination"
} finally {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $temp
}
