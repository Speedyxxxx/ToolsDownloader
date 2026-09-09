#Requires -Version 7.0

[CmdletBinding()]
param()

# ── Privilege check ───────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script requires Administrator privileges.' -ForegroundColor Red
    Write-Host 'Please re-run from an elevated PowerShell session.' -ForegroundColor Yellow
    exit 1
}

$ProgressPreference = 'SilentlyContinue'

# ── ANSI palette ──────────────────────────────────────────────────────────────
$e = [char]27

$White       = "${e}[38;2;245;245;245m"
$Grey        = "${e}[38;2;190;190;190m"
$Gray        = "${e}[38;2;125;125;125m"
$SpeedyWhite = "${e}[38;2;255;255;255m"

$Green       = "${e}[38;2;80;220;80m"
$Red         = "${e}[91m"

$Reset       = "${e}[0m"
$Bold        = "${e}[1m"

# ── Tool groups ───────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    'Orbdiff' = @(
        'https://github.com/Orbdiff/BAMReveal/releases/download/v1.3.1/BAMReveal.exe'
        'https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.8/pv++.exe'
        'https://github.com/Orbdiff/MFT-HardLink/releases/download/v1.2/HardLink.exe'
        'https://github.com/Orbdiff/Fileless/releases/download/v1.3/fileless.exe'
        'https://github.com/Orbdiff/DPS-Analyzer/releases/download/v1.1/dpsanalyzer.exe'
        'https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe'
        'https://github.com/Orbdiff/StringsParser/releases/download/v1.2.1b/stringsparser.1.2.1b.exe'
        'https://github.com/Orbdiff/InjGen/releases/download/fork/InjGen.exe'
        'https://github.com/Orbdiff/AmcacheParser/releases/download/v1.0/AmcacheParser.exe'
        'https://github.com/Orbdiff/UserAssistView/releases/download/v1.0/UserAssistView.exe'
    )
    'Spokwn' = @(
        'https://github.com/spokwn/JournalTrace/releases/latest/download/JournalTrace.exe'
        'https://github.com/spokwn/BAM-parser/releases/latest/download/BAMParser.exe'
        'https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe'
        'https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe'
        'https://github.com/spokwn/Replaceparser/releases/latest/download/Replaceparser.exe'
        'https://github.com/spokwn/BamDeletedKeys/releases/latest/download/BamDeletedKeys.exe'
        'https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe'
        'https://github.com/spokwn/Replaceparser/releases/download/v1.1-recode/ReplaceParser.exe'
    )
    'Tonynoh' = @(
        'https://github.com/MeowTonynoh/MeowClientFucker/releases/download/V1.1/MeowClientFucker.exe'
        'https://github.com/MeowTonynoh/MeowResolver/releases/download/v.1.1/MeowResolver.exe'
        'https://github.com/MeowTonynoh/MeowImportsChecker/releases/download/MeowImportsChecker/MeowImportsChecker.exe'
        'https://github.com/MeowTonynoh/MeowDoomsdayFucker/releases/download/V.1.6/MeowDoomsdayFucker.exe'
        'https://github.com/MeowTonynoh/MeowNovowareFucker/releases/download/V2/MeowNovowareFucker.exe'
    )
    'Nirsoft' = @(
        'https://www.nirsoft.net/utils/lastactivityview.zip'
        'https://www.nirsoft.net/utils/executedprogramslist.zip'
        'https://www.nirsoft.net/utils/alternatestreamview-x64.zip'
        'https://www.nirsoft.net/utils/clipboardic.zip'
        'https://www.nirsoft.net/utils/networkusageview-x64.zip'
    )
    'Eric Zimmerman' = @(
        'https://download.ericzimmermanstools.com/net9/PECmd.zip'
        'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'
        'https://download.ericzimmermanstools.com/net9/JLECmd.zip'
        'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'
        'https://download.ericzimmermanstools.com/net9/bstrings.zip'
        'https://download.ericzimmermanstools.com/net9/RecentFileCacheParser.zip'
        'https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/ShellBagsExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip'
        'https://download.ericzimmermanstools.com/AppCompatCacheParser.zip'
        'https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.308/dotnet-sdk-9.0.308-win-x64.exe'

    )
    'Generic Tools' = @(
        'https://github.com/winsiderss/si-builds/releases/download/4.0.26245.218/systeminformer-build-canary-setup.exe'
        'https://www.voidtools.com/Everything-1.4.1.1029.x64-Setup.exe'
        'https://www.dropbox.com/scl/fi/q428cz9l0uq50bg3azh57/AccessData_FTK_Imager_4.7.1.exe?rlkey=o6w5ot98zb3wpo12n4rlwowhb&st=230sgk3i&dl=1'
        'https://raw.githubusercontent.com/Speedyxxxx/AltChecker/main/AltChecker.exe'
        'https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip'
        'https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe'
        'https://github.com/Col-E/Recaf/releases/download/2.21.14/recaf-2.21.14-J8-jar-with-dependencies.jar'
        'https://download.sysinternals.com/files/TCPView.zip'
        'https://github.com/Yamato-Security/hayabusa/releases/download/v3.10.0/hayabusa-3.10.0-win-x64.zip'
        'https://github.com/Inkenal/RegistryScanner/releases/download/main/RegistryScanner.exe'
        'https://github.com/p1aegg/javaw/releases/download/v1.12/P1AE.Javaw.exe'
        'https://github.com/Inkenal/TaskParser/releases/download/main/VigilsTaskParser.exe'
        'https://github.com/Sorted1/StormSS-Fuser-Finder/releases/download/Main/Storm.Fuser.Finder.zip'
    )
    'Detect' = @(
        'https://detect.ac/tool/ToolsDownloader++'
    )
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-NextSSFolder {
    $i = 1
    while (Test-Path "C:\ss$i") { $i++ }
    return "C:\ss$i"
}

function Get-FilenameFromUrl {
    param([string]$Url)
    $path = ([System.Uri]$Url).AbsolutePath
    return [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($path))
}
# ── Fast sequential HTTP client ───────────────────────────────────────────────
$HttpHandler = [System.Net.Http.HttpClientHandler]::new()
$HttpHandler.AutomaticDecompression = [System.Net.DecompressionMethods]::All

$HttpClient = [System.Net.Http.HttpClient]::new($HttpHandler)
$HttpClient.Timeout = [TimeSpan]::FromMinutes(10)
$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
    'Speedyxx-ToolsDownloader/2.0'
)

# Larger buffer = less I/O overhead for larger downloads
$CopyBufferSize = 65536
function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$GroupFolder,
        [System.Collections.Generic.List[string]]$FailedList
    )

    $filename = Get-FilenameFromUrl -Url $Url

    if ([string]::IsNullOrWhiteSpace($filename)) {
        Write-Host "    ${Red}✗ URL has no downloadable filename: $Url${Reset}"
        $FailedList.Add($Url)
        return
    }

    $isZip = $filename -match '\.zip$'

    if ($isZip) {
        $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $tempZip    = Join-Path $GroupFolder $filename
        $extractDir = Join-Path $GroupFolder $baseName

       $n = 2
    while ((Test-Path $tempZip) -or (Test-Path $extractDir)) {
    $tempZip = Join-Path $GroupFolder ("{0}_{1}.zip" -f $baseName, $n)
    $extractDir = Join-Path $GroupFolder ("{0}_{1}" -f $baseName, $n)
    $n++
}

$destPath = $tempZip
    }
    else {
        $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $extension = [System.IO.Path]::GetExtension($filename)
        $destPath  = Join-Path $GroupFolder $filename

        $n = 2
        while (Test-Path $destPath) {
            $destPath = Join-Path $GroupFolder ("{0}_{1}{2}" -f $baseName, $n, $extension)
            $n++
        }
    }

    Write-Host "    ${DkOrange}↓ ${Orange}$filename${Reset} " -NoNewline

    $response = $null
    $stream = $null
    $fileStream = $null

    try {
    $response = $HttpClient.GetAsync($Url).GetAwaiter().GetResult()
    $response.EnsureSuccessStatusCode()
    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    
        $fileStream = [System.IO.FileStream]::new(
            $destPath,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            $CopyBufferSize,
            [System.IO.FileOptions]::SequentialScan
        )

        $stream.CopyToAsync(
            $fileStream,
            $CopyBufferSize
        ).GetAwaiter().GetResult()

        if ($isZip) {
            $fileStream.Dispose()
            $fileStream = $null

            $null = New-Item -ItemType Directory -Path $extractDir -Force

            [System.IO.Compression.ZipFile]::ExtractToDirectory(
                $destPath,
                $extractDir,
                $true
            )

            Remove-Item -Path $destPath -Force
        }

        Write-Host "${Green}✓${Reset}"
    }
    catch {
        Write-Host "${Red}✗${Reset}"
        Write-Host "      ${Gray}$($_.Exception.Message)${Reset}"
        $FailedList.Add($Url)

        if ($fileStream) {
            $fileStream.Dispose()
            $fileStream = $null
        }

        if (Test-Path $destPath) {
            Remove-Item $destPath -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        if ($fileStream) {
            $fileStream.Dispose()
        }

        if ($stream) {
            $stream.Dispose()
        }

        if ($response) {
            $response.Dispose()
        }
    }
}
function Show-Banner {
    Clear-Host


    # STARS wordmark
    Write-Host "${White}${Grey} ███████╗████████╗ █████╗ ██████╗ ███████╗ ${Reset}"
    Write-Host "${White}${Grey} ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ${Reset}"
    Write-Host "${White}${Grey} ███████╗   ██║   ███████║██████╔╝███████╗ ${Reset}"
    Write-Host "${White}${Grey} ╚════██║   ██║   ██╔══██║██╔══██╗╚════██║ ${Reset}"
    Write-Host "${White}${Grey} ███████║   ██║   ██║  ██║██║  ██║███████║ ${Reset}"
    Write-Host "${White}${Grey} ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ${Reset}"
    Write-Host ""
    Write-Host "${Gray}   Tools Downloader from Speedyxx  •  v1.0${Reset}"
    Write-Host "${White}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
    Write-Host ""
}


# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

$ssFolder   = Get-NextSSFolder
$totalTools = ($Groups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

Write-Host "  ${Orange}Output folder  ${Gold}$ssFolder${Reset}"
Write-Host "  ${Orange}Total tools    ${Gold}$totalTools${Reset} ${Gray}across $($Groups.Count) groups${Reset}"
Write-Host ""

# ── Download mode prompt ──────────────────────────────────────────────────────
Write-Host "  ${Gold}Download mode:${Reset}"
Write-Host ""
Write-Host "    ${DkOrange}[A]${Orange}  All tools ${Gray}($totalTools files)${Reset}"
Write-Host "    ${DkOrange}[C]${Orange}  Choose specific groups${Reset}"
Write-Host ""
$mode = (Read-Host "  >").Trim().ToUpper()

[string[]]$selectedNames = @()

if ($mode -eq 'A') {
    $selectedNames = @($Groups.Keys)
} elseif ($mode -eq 'C') {
    Write-Host ""
    $groupKeys = @($Groups.Keys)
    Write-Host "  ${Gold}Available groups:${Reset}"
    Write-Host ""
    for ($i = 0; $i -lt $groupKeys.Count; $i++) {
        $cnt = $Groups[$groupKeys[$i]].Count
        Write-Host "    ${DkOrange}[$($i + 1)]${Orange} $($groupKeys[$i]) ${Gray}($cnt tools)${Reset}"
    }
    Write-Host ""
    Write-Host "  ${Gold}Enter group numbers separated by commas ${Gray}(e.g. 1,3,5)${Gold}:${Reset}"
    $raw = (Read-Host "  >").Trim()

    foreach ($part in ($raw -split ',')) {
        $part = $part.Trim()
        if ($part -match '^\d+$') {
            $idx = [int]$part - 1
            if ($idx -ge 0 -and $idx -lt $groupKeys.Count) {
                $selectedNames += $groupKeys[$idx]
            }
        }
    }

    if ($selectedNames.Count -eq 0) {
        Write-Host ""
        Write-Host "  ${Red}No valid groups selected. Exiting.${Reset}"
        exit 0
    }
} else {
    Write-Host ""
    Write-Host "  ${Red}Invalid choice. Exiting.${Reset}"
    exit 0
}

# ── Confirmation ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Selected groups:${Reset}"
Write-Host ""
$totalSelected = 0
foreach ($name in $selectedNames) {
    $cnt = $Groups[$name].Count
    $totalSelected += $cnt
    Write-Host "    ${Grey}• $name ${Gray}($cnt tools)${Reset}"
}
Write-Host ""
Write-Host "  ${White}Files to download: ${Orange}$totalSelected${Reset}"
Write-Host ""
$confirm = (Read-Host "  ${Grey}Proceed? [Y/N]  >${Reset}").Trim().ToUpper()
if ($confirm -ne 'Y') {
    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ── Setup output folder + AV exclusion ───────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Creating ${Grey}$ssFolder${Orange}...${Reset}" -NoNewline
$null = New-Item -ItemType Directory -Path $ssFolder -Force
Write-Host " ${Green}✓${Reset}"

Write-Host "  ${White}Adding Windows Defender exclusion...${Reset}" -NoNewline
if (-not (Get-Command -Name 'Add-MpPreference' -ErrorAction SilentlyContinue)) {
    Write-Host " ${Gray}skipped (Defender not present)${Reset}"
} else {
    try {
        Add-MpPreference -ExclusionPath $ssFolder -ErrorAction Stop
        Write-Host " ${Green}✓${Reset}"
    } catch {
        Write-Host " ${Red}✗ (non-fatal — $_)${Reset}"
    }
}

# ── Download ──────────────────────────────────────────────────────────────────
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {
    $urls     = $Groups[$groupName]
    $groupDir = Join-Path $ssFolder $groupName
    $null = New-Item -ItemType Directory -Path $groupDir -Force

    Write-Host ""
    Write-Host "  ${White}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    foreach ($url in $urls) {
        Invoke-FileDownload -Url $url -GroupFolder $groupDir -FailedList $failed
    }
}

# ── Automatic forensic tools ──────────────────────────────────────────────────
if ($ssFolder -eq 'C:\ss1') {
    Write-Host ""
    Write-Host "  ${White}Running automatic tools for C:\ss1...${Reset}"
    Write-Host ""

    # Open shell:recent
    Write-Host "  ${Grey}Opening Recent Items...${Reset}"
    Start-Process explorer.exe -ArgumentList 'shell:recent'

    # Find downloaded tools
    $mfteCmd = Get-ChildItem -Path $ssFolder -Filter 'MFTECmd.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    $appCompat = Get-ChildItem -Path $ssFolder -Filter 'AppCompatCacheParser.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    $srum = Get-ChildItem -Path $ssFolder -Filter 'SrumECmd.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    # MFTECmd
    if ($mfteCmd) {
        Write-Host "  ${Grey}Starting MFTECmd...${Reset}"

        $cmd = "cd /d `"$($mfteCmd.Directory.FullName)`" && MFTECmd.exe --at -f C:`$MFT --csv ."

        Start-Process cmd.exe `
            -Verb RunAs `
            -ArgumentList "/k $cmd"
    }
    else {
        Write-Host "  ${Red}MFTECmd.exe not found.${Reset}"
    }

    # AppCompatCacheParser
    if ($appCompat) {
        Write-Host "  ${Grey}Starting AppCompatCacheParser...${Reset}"

        $cmd = "cd /d `"$($appCompat.Directory.FullName)`" && AppCompatCacheParser.exe --csv ."

        Start-Process cmd.exe `
            -Verb RunAs `
            -ArgumentList "/k $cmd"
    }
    else {
        Write-Host "  ${Red}AppCompatCacheParser.exe not found.${Reset}"
    }

    # SrumECmd
    if ($srum) {
        Write-Host "  ${Grey}Starting SrumECmd...${Reset}"

        $cmd = "cd /d `"$($srum.Directory.FullName)`" && SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv ."

        Start-Process cmd.exe `
            -Verb RunAs `
            -ArgumentList "/k $cmd"
    }
    else {
        Write-Host "  ${Red}SrumECmd.exe not found.${Reset}"
    }

    Write-Host ""
    Write-Host "  ${Green}✓ Automatic tools launched.${Reset}"
}

# ── Summary ───────────────────────────────────────────────────────────────────
$succeeded = $totalSelected - $failed.Count

Write-Host ""
Write-Host "  ${White}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host "  ${Green}✓ Downloaded : $succeeded / $totalSelected${Reset}"

if ($failed.Count -gt 0) {
    Write-Host "  ${Red}✗ Failed     : $($failed.Count)${Reset}"
    Write-Host ""
    Write-Host "  ${Red}Failed URLs:${Reset}"
    foreach ($f in $failed) {
        Write-Host "    ${Gray}$f${Reset}"
    }
}

Write-Host ""
Write-Host "  ${White}Tools saved to ${Gold}$ssFolder${Reset}"
Write-Host "  ${Grey}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""
