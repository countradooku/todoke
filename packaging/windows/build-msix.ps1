<#
.SYNOPSIS
Builds todoke-<version>-windows-<arch>.msix from release binaries.

.DESCRIPTION
Stages todoke-desktop.exe, todoke.exe, todoke_shell.dll (the Explorer
command, when built), the licenses, and logos scaled from
packaging\icons; fills AppxManifest.xml; packs with makeappx; signs with
signtool.

Signing: WINDOWS_CERT_PFX (path to a .pfx) and WINDOWS_CERT_PASSWORD sign
the binaries and the package with a timestamp (WINDOWS_TIMESTAMP_URL,
default DigiCert's), and the package's Publisher becomes the certificate's
subject. Without them a throwaway self-signed certificate (subject =
Publisher) signs the package, and its public half is written next to it as
todoke-test-signing.cer: for CI and local tests only.

Release builds keep sessions disabled (no unaudited-dev feature).

.EXAMPLE
cargo build --release --locked -p todoke-desktop -p todoke-cli -p todoke-shell-windows
./packaging/windows/build-msix.ps1 -Arch x64
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    # Where the release binaries are (default target\release).
    [string]$BinDir,
    # Four-part package version (default: the workspace version and .0).
    [string]$Version,
    # The package's Publisher (default: WINDOWS_PUBLISHER, the certificate's
    # subject, or CN=todoke).
    [string]$Publisher,
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

function Invoke-Tool([string]$Tool, [string[]]$Arguments) {
    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path -Leaf $Tool) failed ($LASTEXITCODE)" }
}

# A logo of Width x Height with the icon centered, Scale of the short side.
function New-Logo([string]$Source, [int]$Width, [int]$Height, [double]$Scale, [string]$Target) {
    $image = [System.Drawing.Image]::FromFile($Source)
    try {
        $bitmap = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $side = [int][Math]::Round([Math]::Min($Width, $Height) * $Scale)
                $x = [int][Math]::Floor(($Width - $side) / 2)
                $y = [int][Math]::Floor(($Height - $side) / 2)
                $graphics.DrawImage($image, $x, $y, $side, $side)
            } finally { $graphics.Dispose() }
            $bitmap.Save($Target, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $bitmap.Dispose() }
    } finally { $image.Dispose() }
}

$workspaceVersion = Get-WorkspaceVersion
if (-not $Version) {
    if ($workspaceVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "MSIX versions are four integers; pass -Version for $workspaceVersion"
    }
    $Version = "$workspaceVersion.0"
    $fileVersion = $workspaceVersion
} else {
    $fileVersion = $Version
}
if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw "not a four-part version: $Version" }

$makeappx = Find-SdkTool 'makeappx.exe'
$signtool = Find-SdkTool 'signtool.exe'

foreach ($name in 'todoke-desktop.exe', 'todoke.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir $name))) { throw "no $name in $BinDir" }
}
$shell = Join-Path $BinDir 'todoke_shell.dll'
$withShell = Test-Path -LiteralPath $shell
if (-not $withShell) {
    Write-Warning 'todoke_shell.dll is not built: the package has no Explorer command'
}

# The signing certificate, in the user's store while this script runs.
$pfx = $env:WINDOWS_CERT_PFX
$imported = $false
$testSigned = -not $pfx
if ($testSigned) {
    if (-not $Publisher) { $Publisher = if ($env:WINDOWS_PUBLISHER) { $env:WINDOWS_PUBLISHER } else { 'CN=todoke' } }
    Write-Warning "WINDOWS_CERT_PFX is not set: test-signing with a self-signed certificate for $Publisher"
    $certificate = New-SelfSignedCertificate -Type Custom -Subject $Publisher -KeyUsage DigitalSignature `
        -FriendlyName 'todoke test signing' -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddDays(7) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
} else {
    if (-not $env:WINDOWS_CERT_PASSWORD) { throw 'WINDOWS_CERT_PFX needs WINDOWS_CERT_PASSWORD' }
    $password = ConvertTo-SecureString -String $env:WINDOWS_CERT_PASSWORD -AsPlainText -Force
    # A certificate already in the store (the maintainer's own) stays there.
    $existing = (Get-PfxData -FilePath $pfx -Password $password).EndEntityCertificates[0].Thumbprint
    $imported = -not (Test-Path -LiteralPath "Cert:\CurrentUser\My\$existing")
    $certificate = Import-PfxCertificate -FilePath $pfx -CertStoreLocation 'Cert:\CurrentUser\My' -Password $password
    if (-not $Publisher) { $Publisher = if ($env:WINDOWS_PUBLISHER) { $env:WINDOWS_PUBLISHER } else { $certificate.Subject } }
    if ($Publisher -ne $certificate.Subject) {
        throw "the Publisher ($Publisher) must equal the certificate's subject ($($certificate.Subject))"
    }
}
$thumbprint = $certificate.Thumbprint

try {
    $stage = Join-Path $root "target\packaging\msix-$Arch"
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    $assets = Join-Path $stage 'Assets'
    New-Item -ItemType Directory -Path $assets -Force | Out-Null
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    Copy-Item -LiteralPath (Join-Path $BinDir 'todoke-desktop.exe'), (Join-Path $BinDir 'todoke.exe') -Destination $stage
    if ($withShell) { Copy-Item -LiteralPath $shell -Destination $stage }
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE-APACHE'), (Join-Path $root 'LICENSE-MIT') -Destination $stage

    Add-Type -AssemblyName System.Drawing
    $icons = Join-Path $root 'packaging\icons'
    New-Logo (Join-Path $icons 'todoke-256.png') 44 44 1.0 (Join-Path $assets 'Square44x44Logo.png')
    New-Logo (Join-Path $icons 'todoke-256.png') 50 50 1.0 (Join-Path $assets 'StoreLogo.png')
    New-Logo (Join-Path $icons 'todoke-512.png') 150 150 0.66 (Join-Path $assets 'Square150x150Logo.png')
    New-Logo (Join-Path $icons 'todoke-512.png') 310 150 0.66 (Join-Path $assets 'Wide310x150Logo.png')

    $manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml')
    if (-not $withShell) {
        $manifest = [regex]::Replace($manifest, '(?s)[ \t]*<!-- @SHELL_BEGIN@.*?<!-- @SHELL_END@ -->\r?\n', '')
    }
    $manifest = $manifest.Replace('@VERSION@', $Version)
    $manifest = $manifest.Replace('@PUBLISHER@', [System.Security.SecurityElement]::Escape($Publisher))
    $manifest = $manifest.Replace('@ARCH@', $Arch)
    if ($manifest -match '@(VERSION|PUBLISHER|ARCH)@') { throw "AppxManifest.xml still has $($Matches[0])" }
    [System.IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, (New-Object System.Text.UTF8Encoding($false)))

    $timestamp = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
    $signArguments = @('sign', '/fd', 'SHA256', '/sha1', $thumbprint, '/s', 'My')
    if (-not $testSigned) {
        $signArguments += @('/tr', $timestamp, '/td', 'SHA256')
        $binaries = @('todoke-desktop.exe', 'todoke.exe')
        if ($withShell) { $binaries += 'todoke_shell.dll' }
        Invoke-Tool $signtool ($signArguments + ($binaries | ForEach-Object { Join-Path $stage $_ }))
    }

    $package = Join-Path $OutDir "todoke-$fileVersion-windows-$Arch.msix"
    if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Force }
    Invoke-Tool $makeappx @('pack', '/o', '/h', 'SHA256', '/d', $stage, '/p', $package)
    Invoke-Tool $signtool ($signArguments + @($package))

    if ($testSigned) {
        Export-Certificate -Cert $certificate -FilePath (Join-Path $OutDir 'todoke-test-signing.cer') | Out-Null
    }
    Write-Output $package
} finally {
    # The private key this script put in the store never outlives the
    # build; one that was there before stays.
    if ($testSigned -or $imported) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -DeleteKey -ErrorAction SilentlyContinue
    }
}
