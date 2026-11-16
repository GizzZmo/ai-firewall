<#
  Laster ned WinDivert 2.2.2, konfigurerer og bygger AI-Firewall med Visual Studio 2022 + vcpkg.
  Kjør fra prosjektroten i "Developer PowerShell for VS 2022":

    powershell -ExecutionPolicy Bypass -File scripts\setup-windows.ps1

  Forutsetter: git, CMake 3.24+, VCPKG_ROOT satt (git clone https://github.com/microsoft/vcpkg; .\vcpkg\bootstrap-vcpkg.bat)
#>
param(
    [string]$WinDivertVersion = "2.2.2",
    [string]$Config = "Release"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$deps = Join-Path $root "third_party"
New-Item -ItemType Directory -Force -Path $deps | Out-Null

if (-not $env:VCPKG_ROOT) { throw "Sett VCPKG_ROOT til vcpkg-mappen din først." }

$wdDir = Join-Path $deps "WinDivert-$WinDivertVersion-A"
if (-not (Test-Path $wdDir)) {
    $zip = Join-Path $deps "WinDivert.zip"
    $url = "https://github.com/basil00/WinDivert/releases/download/v$WinDivertVersion/WinDivert-$WinDivertVersion-A.zip"
    Write-Host "Laster ned $url"
    Invoke-WebRequest -Uri $url -OutFile $zip
    # Kontroller signaturen på driveren før bruk (skal være signert av "Basil Reqrypt"-sertifikat via Microsoft).
    Expand-Archive -Path $zip -DestinationPath $deps -Force
    $sig = Get-AuthenticodeSignature (Join-Path $wdDir "x64\WinDivert64.sys")
    Write-Host "WinDivert64.sys signatur: $($sig.Status) ($($sig.SignerCertificate.Subject))"
    if ($sig.Status -ne "Valid") { Write-Warning "Driversignaturen er ikke gyldig – undersøk før du fortsetter!" }
}
$env:WINDIVERT_DIR = $wdDir

cmake --preset windows-vcpkg
cmake --build --preset windows-release
ctest --preset windows-release

$bin = Join-Path $root "build\windows-vcpkg\$Config"
Copy-Item -Recurse -Force (Join-Path $root "config") $bin
New-Item -ItemType Directory -Force -Path (Join-Path $bin "models") | Out-Null
if (Test-Path (Join-Path $root "models\flow_classifier.onnx")) {
    Copy-Item -Force (Join-Path $root "models\flow_classifier.onnx") (Join-Path $bin "models")
}
Write-Host "`nFerdig. Test i konsollmodus (som administrator):`n  $bin\aifw_service.exe --console"
