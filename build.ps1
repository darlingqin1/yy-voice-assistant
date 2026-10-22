param([switch]$Package)
$ErrorActionPreference = 'Stop'
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '需要 Windows 64 位与 .NET Framework 桌面组件。' }
$output = Join-Path $PSScriptRoot 'dist\YY语音助手'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$wpf = Join-Path $framework 'WPF'
$references = @('PresentationCore.dll','PresentationFramework.dll','WindowsBase.dll','UIAutomationClient.dll','UIAutomationTypes.dll') | ForEach-Object { '/r:' + (Join-Path $wpf $_) }
$exe = Join-Path $output 'YY语音助手.exe'
& $compiler /nologo /utf8output /codepage:65001 /target:winexe /platform:x64 /optimize+ ('/out:' + $exe) /r:System.Xaml.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll $references (Join-Path $PSScriptRoot 'src\YYAssistant.cs') (Join-Path $PSScriptRoot 'src\Updates.cs')
if ($LASTEXITCODE -ne 0) { throw '编译失败。' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'assets\开麦.wav'),(Join-Path $PSScriptRoot 'assets\关麦.wav') -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $output '使用说明.txt') -Force
if ($Package) {
    $zip = Join-Path $PSScriptRoot 'dist\YY-Voice-Assistant-v0.1.4-win-x64.zip'
    # Use an explicit allowlist so building after a local run cannot publish settings or logs.
    $files = @('YY语音助手.exe','开麦.wav','关麦.wav','使用说明.txt') | ForEach-Object { Join-Path $output $_ }
    Compress-Archive -LiteralPath $files -DestinationPath $zip -Force
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(($zip + '.sha256'),($hash + '  ' + [IO.Path]::GetFileName($zip) + [Environment]::NewLine),[Text.Encoding]::ASCII)
    Write-Output $zip
}
