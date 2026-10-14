<#
.SYNOPSIS
Builds the portable todoke-<version>-windows-<arch>.zip (Scoop, winget).

.DESCRIPTION
todoke.exe, todoke-desktop.exe, and the licenses, at the archive's root.
With WINDOWS_CERT_PFX and WINDOWS_CERT_PASSWORD the executables are signed
and timestamped (WINDOWS_TIMESTAMP_URL, default DigiCert's); otherwise they
are left unsigned. An unpackaged install has no Explorer COM command: the
app writes per-user registry verbs (HKCU) itself.

.EXAMPLE
cargo build --release --locked -p todoke-desktop -p todoke-cli
./packaging/windows/build-zip.ps1 -Arch x64
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    # Where the release binaries are (default target\release).
    [string]$BinDir,
    # Version in the file name (default: the workspace version).
    [string]$Version,
    [string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $BinDir) { $BinDir = Join-Path $root 'target\release' }
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

function Get-WorkspaceVersion {
    $section = ''
    foreach ($line in Get-Content -LiteralPath (Join-Path $root 'Cargo.toml')) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') { $section = $Matches[1]; continue }
        if ($section -eq 'workspace.package' -and $line -match '^\s*version\s*=\s*"([^"]+)"') {
            return $Matches[1]
        }
    }
    throw 'no [workspace.package] version in Cargo.toml'
}

function Find-SdkTool([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -LiteralPath $kits -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$Name" } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if (-not $found) { throw "$Name not found: install the Windows SDK" }
    return $found
}

if (-not $Version) { $Version = Get-WorkspaceVersion }
$binaries = @('todoke.exe', 'todoke-desktop.exe')
foreach ($name in $binaries) {
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir $name))) { throw "no $name in $BinDir" }
}

$stage = Join-Path $root "target\packaging\zip-$Arch"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Copy-Item -LiteralPath ($binaries | ForEach-Object { Join-Path $BinDir $_ }) -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'LICENSE-APACHE'), (Join-Path $root 'LICENSE-MIT') -Destination $stage

if ($env:WINDOWS_CERT_PFX) {
    if (-not $env:WINDOWS_CERT_PASSWORD) { throw 'WINDOWS_CERT_PFX needs WINDOWS_CERT_PASSWORD' }
    $password = ConvertTo-SecureString -String $env:WINDOWS_CERT_PASSWORD -AsPlainText -Force
    $certificate = Import-PfxCertificate -FilePath $env:WINDOWS_CERT_PFX -CertStoreLocation 'Cert:\CurrentUser\My' -Password $password
    try {
        $timestamp = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
        $signtool = Find-SdkTool 'signtool.exe'
        & $signtool sign /fd SHA256 /sha1 $certificate.Thumbprint /s My /tr $timestamp /td SHA256 `
            ($binaries | ForEach-Object { Join-Path $stage $_ })
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
    } finally {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
} else {
    Write-Warning 'WINDOWS_CERT_PFX is not set: the executables are unsigned'
}

$archive = Join-Path $OutDir "todoke-$Version-windows-$Arch.zip"
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
Write-Output $archive
