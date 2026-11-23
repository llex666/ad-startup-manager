#Requires -Version 5.1
<#
.SYNOPSIS
    Интерактивная консоль (в стиле sconfig) для проверки и редактирования
    автозагрузки на всех компьютерах, серверах и ВМ домена.

.DESCRIPTION
    Источники автозагрузки:
      * Реестр Run      : HKLM\...\Run, HKLM\...\WOW6432Node\...\Run (x86) и HKU\<SID>\...\Run
                          для ВСЕХ профилей пользователей (незагруженные NTUSER.DAT
                          временно подключаются и затем отключаются);
      * Папки Startup   : общая (ProgramData) и папки всех профилей;
      * Задания планировщика с триггером «при входе» / «при загрузке»
                          (по умолчанию без системных \Microsoft\*).

    Включение/отключение выполняется так же, как в Диспетчере задач
    (ключи StartupApproved), для заданий - Enable/Disable-ScheduledTask.
    Удаление - безвозвратное (команда удалённого элемента пишется в лог).

    Требования: запуск от доменного администратора, RSAT (ActiveDirectory),
    на целевых компьютерах включён WinRM (порт 5985).
    Файл сохранён в UTF-8 с BOM для корректной кириллицы в PowerShell 5.1.

.EXAMPLE
    .\Manage-DomainStartup.ps1 -Domain corp.example.com -StaleDays 60
#>

[CmdletBinding()]
param(
    # DNS-имя домена AD (по умолчанию - домен текущего пользователя)
    [string]$Domain = $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { 'example.local' }),

    # Пропускать компьютеры, не заходившие в домен более N дней
    [int]$StaleDays = 90
)

# ----------------------------- НАСТРОЙКИ ------------------------------------
$LogBase   = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
$LogPath   = Join-Path $LogBase 'DomainStartupManager.log'
# ----------------------------------------------------------------------------

Import-Module ActiveDirectory -ErrorAction Stop

$script:Computers = @()
$script:CompMap   = @{}
$script:Items     = @()
$script:ShowTasks = $true     # показывать задания планировщика (вход/загрузка)
$script:ShowMS    = $false    # показывать системные задания \Microsoft\*
$script:LastScan  = $null
$script:ScanType  = 'All'      # All | Client | Server (что сканировать)
$script:ScanOU    = $null      # DN выбранной OU; $null = весь домен

# ======================= КОД, КОТОРЫЙ ВЫПОЛНЯЕТСЯ НА ЦЕЛЕВЫХ ПК =======================
$script:RemoteBlock = {
    param([string]$Op, $Records)
    $ErrorActionPreference = 'SilentlyContinue'
    $comp = $env:COMPUTERNAME
    $CV   = 'SOFTWARE\Microsoft\Windows\CurrentVersion'
    $HKLM = @{ Base = [Microsoft.Win32.Registry]::LocalMachine; Prefix = '' }

    function Open-K($ctx, $sub, [bool]$write = $false) {
        try { $ctx.Base.OpenSubKey($ctx.Prefix + $sub, $write) } catch { $null }
    }

    function Get-Approved($ctx, $sub, $name) {
        $k = Open-K $ctx "$CV\Explorer\StartupApproved\$sub"
        if (-not $k) { return $true }
        try { $v = $k.GetValue($name) } finally { $k.Close() }
        if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 0) }
        $true
    }

    function Set-Approved($ctx, $sub, $name, [bool]$enable) {
        $k = $ctx.Base.CreateSubKey($ctx.Prefix + "$CV\Explorer\StartupApproved\$sub")
        try {
            if ($enable) { $b = [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) }
            else { $b = [byte[]]([byte[]](3,0,0,0) + [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())) }
            $k.SetValue($name, $b, [Microsoft.Win32.RegistryValueKind]::Binary)
        } finally { $k.Close() }
    }

    function Remove-Approved($ctx, $sub, $name) {
        $k = Open-K $ctx "$CV\Explorer\StartupApproved\$sub" $true
        if ($k) { try { $k.DeleteValue($name, $false) } finally { $k.Close() } }
    }

    function Get-UserProfiles {
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($key in (Get-ChildItem $pl)) {
            $sid = $key.PSChildName
            if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
            $pp = (Get-ItemProperty $key.PSPath).ProfileImagePath
            if (-not $pp) { continue }
            $name = $null
            try { $name = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
            if (-not $name) { $name = Split-Path $pp -Leaf }
            [pscustomobject]@{ Sid = $sid; Path = $pp; Name = $name }
        }
    }

    function Invoke-WithUserHive($Sid, [scriptblock]$Script) {
        $users = [Microsoft.Win32.Registry]::Users
        $k = $users.OpenSubKey($Sid)
        if ($k) { $k.Close(); & $Script @{ Base = $users; Prefix = "$Sid\" }; return }
        $pp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid").ProfileImagePath
        if (-not $pp) { throw 'Профиль пользователя не найден' }
        $dat = Join-Path $pp 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { throw 'Нет файла NTUSER.DAT' }
        $tmp = 'TmpHive_' + ($Sid -replace '-', '_')
        $null = & reg.exe load "HKU\$tmp" $dat 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить профиль пользователя (файл занят?)' }
        try { & $Script @{ Base = $users; Prefix = "$tmp\" } }
        finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $null = & reg.exe unload "HKU\$tmp" 2>&1
        }
    }

    function Get-StartupItems($ctx, $scope, $hive, $folder, [bool]$wow) {
        $defs = @(@{ Sub = "$CV\Run"; Appr = 'Run'; Src = 'Run' })
        if ($wow) { $defs += @{ Sub = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Appr = 'Run32'; Src = 'Run32' } }
        foreach ($d in $defs) {
            $k = Open-K $ctx $d.Sub
            if (-not $k) { continue }
            try {
                foreach ($n in $k.GetValueNames()) {
                    if ($n -eq '') { continue }
                    [pscustomobject]@{
                        Computer = $comp; Source = $d.Src; Scope = $scope; Hive = $hive
                        Location = $d.Sub; Appr = $d.Appr; Name = $n
                        Command = [string]$k.GetValue($n); Detail = ''
                        Enabled = [bool](Get-Approved $ctx $d.Appr $n)
                    }
                }
            } finally { $k.Close() }
        }
        if ($folder -and (Test-Path -LiteralPath $folder)) {
            $wsh = $null
            foreach ($f in (Get-ChildItem -LiteralPath $folder -File -Force)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $cmd = $f.FullName
                if ($f.Extension -eq '.lnk') {
                    try {
                        if (-not $wsh) { $wsh = New-Object -ComObject WScript.Shell }
                        $sc = $wsh.CreateShortcut($f.FullName)
                        $cmd = ("$($sc.TargetPath) $($sc.Arguments)").Trim()
                    } catch { }
                }
                [pscustomobject]@{
                    Computer = $comp; Source = 'Folder'; Scope = $scope; Hive = $hive
                    Location = $folder; Appr = 'StartupFolder'; Name = $f.Name
                    Command = $cmd; Detail = ''
                    Enabled = [bool](Get-Approved $ctx 'StartupFolder' $f.Name)
                }
            }
        }
    }

    function Get-TaskItems {
        try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { return }
        foreach ($t in $tasks) {
            $trg = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName })
            $logon = $trg -contains 'MSFT_TaskLogonTrigger'
            $boot  = $trg -contains 'MSFT_TaskBootTrigger'
            if (-not ($logon -or $boot)) { continue }
            $detail = (@($(if ($logon) { 'вход' }), $(if ($boot) { 'загрузка' })) | Where-Object { $_ }) -join '+'
            $runAs  = if ($t.Principal.UserId) { $t.Principal.UserId } else { 'Система' }
            $cmd = (@($t.Actions) | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join ' ; '
            [pscustomobject]@{
                Computer = $comp; Source = 'Task'; Scope = $runAs; Hive = ''
                Location = $t.TaskPath; Appr = ''; Name = $t.TaskName
                Command = $cmd; Detail = $detail
                Enabled = [bool]($t.State -ne 'Disabled')
            }
        }
    }

    function Invoke-RegOp($ctx, $r, $Op) {
        if ($r.Source -eq 'Folder') {
            switch ($Op) {
                'Delete'  { Remove-Item -LiteralPath (Join-Path $r.Location $r.Name) -Force -ErrorAction Stop
                            Remove-Approved $ctx $r.Appr $r.Name }
                'Disable' { Set-Approved $ctx $r.Appr $r.Name $false }
                'Enable'  { Set-Approved $ctx $r.Appr $r.Name $true }
            }
        } else {
            switch ($Op) {
                'Delete' {
                    $k = Open-K $ctx $r.Location $true
                    if (-not $k) { throw 'Ключ реестра не найден' }
                    try { $k.DeleteValue($r.Name) } finally { $k.Close() }
                    Remove-Approved $ctx $r.Appr $r.Name
                }
                'Disable' { Set-Approved $ctx $r.Appr $r.Name $false }
                'Enable'  { Set-Approved $ctx $r.Appr $r.Name $true }
            }
        }
    }

    # ------------------------------- Сбор -------------------------------
    if ($Op -eq 'Collect') {
        Get-StartupItems $HKLM 'Система' 'HKLM' "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" $true
        foreach ($p in (Get-UserProfiles)) {
            try {
                Invoke-WithUserHive $p.Sid {
                    param($ctx)
                    Get-StartupItems $ctx $p.Name $p.Sid ($p.Path + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') $false
                }
            } catch { }
        }
        Get-TaskItems
        return
    }

    # ----------------------------- Действия -----------------------------
    $mine = @($Records | Where-Object { $_.Computer -eq $comp })
    foreach ($r in $mine) {
        $res = [pscustomobject]@{ Computer = $comp; IdKey = $r.IdKey; Ok = $false; Message = '' }
        try {
            if ($r.Source -eq 'Task') {
                switch ($Op) {
                    'Enable'  { $null = Enable-ScheduledTask  -TaskName $r.Name -TaskPath $r.Location -ErrorAction Stop }
                    'Disable' { $null = Disable-ScheduledTask -TaskName $r.Name -TaskPath $r.Location -ErrorAction Stop }
                    'Delete'  { Unregister-ScheduledTask -TaskName $r.Name -TaskPath $r.Location -Confirm:$false -ErrorAction Stop }
                }
            }
            elseif ($r.Hive -eq 'HKLM') { Invoke-RegOp $HKLM $r $Op }
            else { Invoke-WithUserHive $r.Hive { param($ctx) Invoke-RegOp $ctx $r $Op } }
            $res.Ok = $true
        } catch {
            $res.Message = (($_.Exception.Message) -split "`n")[0]
        }
        $res
    }
}
# =======================================================================================

# ------------------------------ Вспомогательное -----------------------------

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $env:USERNAME, $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Read-Key {
    try { [Console]::ReadKey($true).KeyChar.ToString() }
    catch { Read-Host }
}

function Wait-Key {
    Write-Host ''
    Write-Host 'Нажмите любую клавишу для возврата в меню...' -ForegroundColor DarkGray
    [void](Read-Key)
}

function Limit-Text {
    param($Text, [int]$Max = 70)
    $s = [string]$Text
    if ($s.Length -gt $Max) { $s.Substring(0, $Max - 1) + '…' } else { $s }
}

function Write-Header {
    param([string]$Title)
    Clear-Host
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host ''
}

function Get-SourceName {
    param($Source)
    switch ($Source) {
        'Run'    { 'Реестр Run' }
        'Run32'  { 'Реестр Run (x86)' }
        'Folder' { 'Папка Startup' }
        'Task'   { 'Планировщик' }
        default  { $Source }
    }
}

function Test-PortAsync {
    param([string[]]$Names, [int]$Port, [int]$TimeoutMs = 3000)
    $clients = @{}; $tasks = @{}
    foreach ($n in $Names) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $clients[$n] = $c
            $tasks[$n]   = $c.ConnectAsync($n, $Port)
        } catch { }
    }
    try {
        [void][System.Threading.Tasks.Task]::WaitAll(
            [System.Threading.Tasks.Task[]]@($tasks.Values), $TimeoutMs)
    } catch { }
    $res = @{}
    foreach ($n in $Names) {
        $res[$n] = ($tasks.ContainsKey($n) -and
                    $tasks[$n].Status -eq 'RanToCompletion' -and
                    $clients[$n].Connected)
        if ($clients.ContainsKey($n)) { $clients[$n].Dispose() }
    }
    $res
}

function Get-VisibleItems {
    param([string]$Type)
    $items = $script:Items
    if (-not $script:ShowTasks) { $items = $items | Where-Object { $_.Source -ne 'Task' } }
    if (-not $script:ShowMS)    { $items = $items | Where-Object { -not ($_.Source -eq 'Task' -and $_.Location -like '\Microsoft\*') } }
    if ($Type)                  { $items = $items | Where-Object { $_.Type -eq $Type } }
    @($items)
}

function Get-ItemGroups {
    param([string]$Filter)
    $items = Get-VisibleItems
    if ($Filter) { $items = $items | Where-Object { $_.Name -like "*$Filter*" -or $_.Command -like "*$Filter*" } }
    @($items | Group-Object -Property Key | Sort-Object { $_.Group[0].SourceName }, Name)
}

function Show-GroupTable {
    param($Groups)
    $i = 0
    $view = foreach ($g in $Groups) {
        $i++
        $f = $g.Group[0]
        [pscustomobject][ordered]@{
            '#'        = $i
            'Источник' = $f.SourceName
            'Область'  = $f.KindName
            'Имя'      = Limit-Text $f.Name 40
            'Клиенты'  = @($g.Group | Where-Object { $_.Type -eq 'Client' }).Count
            'Серверы'  = @($g.Group | Where-Object { $_.Type -eq 'Server' }).Count
            'Откл.'    = @($g.Group | Where-Object { -not $_.Enabled }).Count
            'Всего'    = $g.Count
        }
    }
    $view | Format-Table -AutoSize | Out-Host
}

# ------------------------------- Сканирование -------------------------------

function Get-ScanTypeName {
    switch ($script:ScanType) {
        'Client' { 'только компьютеры пользователей' }
        'Server' { 'только серверы и ВМ' }
        default  { 'все компьютеры' }
    }
}

function Switch-ScanType {
    $script:ScanType = switch ($script:ScanType) { 'All' { 'Client' } 'Client' { 'Server' } default { 'All' } }
}

function Clear-Results {
    $script:Computers = @(); $script:Items = @(); $script:CompMap = @{}; $script:LastScan = $null
}

function Update-CompMap {
    $script:CompMap = @{}
    foreach ($c in $script:Computers) { $script:CompMap[$c.Name] = $c }
}

function Test-EscPressed {
    try {
        while ([Console]::KeyAvailable) {
            if ([Console]::ReadKey($true).Key -eq 'Escape') { return $true }
        }
    } catch { }
    $false
}

function Get-ScanTargets {
    $limit = (Get-Date).AddDays(-$StaleDays)
    $p = @{
        Server = $Domain; Filter = 'Enabled -eq $true'
        Properties = 'OperatingSystem', 'LastLogonDate'; ErrorAction = 'Stop'
    }
    if ($script:ScanOU) { $p.SearchBase = $script:ScanOU; $p.SearchScope = 'Subtree' }
    Get-ADComputer @p | Where-Object {
        $_.OperatingSystem -like 'Windows*' -and $_.LastLogonDate -gt $limit -and
        ($script:ScanType -eq 'All' -or
         ($script:ScanType -eq 'Server' -and $_.OperatingSystem -like '*Server*') -or
         ($script:ScanType -eq 'Client' -and $_.OperatingSystem -notlike '*Server*'))
    }
}

function Select-ScanOU {
    Write-Header 'Выбор OU для сканирования'
    Write-Host 'Загружаю список OU из AD...' -ForegroundColor Cyan
    try { $ous = @(Get-ADOrganizationalUnit -Server $Domain -Filter * -ErrorAction Stop | Sort-Object DistinguishedName) }
    catch { Write-Host "Ошибка AD: $($_.Exception.Message)" -ForegroundColor Red; Wait-Key; return }

    Write-Host ("Текущая область: {0}" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host 'Сканируется выбранная OU вместе со всеми вложенными.' -ForegroundColor DarkGray
    Write-Host ''
    $f = Read-Host 'Фильтр по части имени OU (Enter — показать все)'
    $list = if ($f) { @($ous | Where-Object { $_.DistinguishedName -like "*$f*" }) } else { $ous }
    if ($list.Count -eq 0) { Write-Host 'OU не найдены.' -ForegroundColor Yellow; Wait-Key; return }

    $i = 0
    $view = foreach ($o in $list) { $i++; [pscustomobject]@{ '#' = $i; 'OU' = $o.DistinguishedName } }
    $fmt = $view | Format-Table -AutoSize
    try { $fmt | Out-Host -Paging } catch { $fmt | Out-Host }
    Write-Host ''
    $sel = (Read-Host 'Номер OU, либо DN целиком, либо 0 — весь домен (Enter — без изменений)').Trim()
    if (-not $sel) { return }
    if ($sel -eq '0') { $script:ScanOU = $null; return }
    if ($sel -match '^\d+$') {
        $n = [int]$sel
        if ($n -ge 1 -and $n -le $list.Count) { $script:ScanOU = $list[$n - 1].DistinguishedName }
        else { Write-Host 'Неверный номер.' -ForegroundColor Yellow; Wait-Key }
        return
    }
    if ($sel -match '^(OU|CN|DC)=') {
        try { $null = Get-ADObject -Identity $sel -Server $Domain -ErrorAction Stop; $script:ScanOU = $sel }
        catch { Write-Host 'Такой объект в AD не найден.' -ForegroundColor Red; Wait-Key }
        return
    }
    Write-Host 'Неверный ввод.' -ForegroundColor Yellow; Wait-Key
}

function Invoke-Scan {
    Write-Header 'Сканирование'
    Write-Host ("Тип компьютеров : {0}" -f (Get-ScanTypeName))
    Write-Host ("Область (OU)    : {0}" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host 'Прервать опрос можно клавишей Esc.' -ForegroundColor DarkGray
    Write-Host ''
    $act = 'Сканирование автозагрузки'
    $sw  = [Diagnostics.Stopwatch]::StartNew()

    # ---- Шаг 1: список компьютеров из AD
    Write-Progress -Id 1 -Activity $act -Status 'Шаг 1 из 3: получаю список компьютеров из AD...' -PercentComplete 0
    try { $ad = @(Get-ScanTargets | Sort-Object Name) }
    catch {
        Write-Progress -Id 1 -Activity $act -Completed
        Write-Host "Ошибка AD: $($_.Exception.Message)" -ForegroundColor Red
        Wait-Key; return
    }
    if ($ad.Count -eq 0) {
        Write-Progress -Id 1 -Activity $act -Completed
        Write-Host 'Подходящих компьютеров не найдено.' -ForegroundColor Yellow
        Wait-Key; return
    }
    Write-Host "Найдено компьютеров: $($ad.Count)" -ForegroundColor Cyan

    # прежние данные заменяются только для сканируемых компьютеров
    $newSet = @{}; foreach ($c in $ad) { $newSet[$c.Name] = $true }
    $script:Computers = @($script:Computers | Where-Object { -not $newSet.ContainsKey($_.Name) })
    $script:Items     = @($script:Items     | Where-Object { -not $newSet.ContainsKey($_.Computer) })

    $new = @(foreach ($c in $ad) {
        [pscustomobject]@{
            Name      = $c.Name
            OS        = $c.OperatingSystem
            Type      = $(if ($c.OperatingSystem -like '*Server*') { 'Server' } else { 'Client' })
            Online    = $false
            Connected = $false
            Error     = ''
        }
    })
    $script:Computers = @($script:Computers) + $new
    Update-CompMap

    # ---- Шаг 2: проверка доступности WinRM
    $names = @($new | Select-Object -ExpandProperty Name)
    $winrm = @{}
    $chunk = 100
    for ($i = 0; $i -lt $names.Count; $i += $chunk) {
        $end  = [math]::Min($i + $chunk, $names.Count)
        $part = @($names[$i..($end - 1)])
        $r = Test-PortAsync -Names $part -Port 5985
        foreach ($k in $r.Keys) { $winrm[$k] = $r[$k] }
        Write-Progress -Id 1 -Activity $act `
            -Status ("Шаг 2 из 3: проверка доступности WinRM: {0} из {1}" -f $end, $names.Count) `
            -PercentComplete ([int](100 * $end / $names.Count))
    }
    foreach ($c in $new) {
        $c.Online = [bool]$winrm[$c.Name]
        $c.Connected = $c.Online
        if (-not $c.Online) { $c.Error = 'Недоступен (выключен или закрыт порт 5985 / WinRM)' }
    }

    # ---- Шаг 3: опрос (фоновое задание + индикатор выполнения)
    $targets  = @($new | Where-Object { $_.Online } | Select-Object -ExpandProperty Name)
    $cancelled = $false
    $okCount = 0
    if ($targets.Count -gt 0) {
        $total = $targets.Count
        $opt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000
        $job = Invoke-Command -ComputerName $targets -ScriptBlock $script:RemoteBlock `
               -ArgumentList 'Collect', $null -SessionOption $opt -ThrottleLimit 32 -AsJob
        while ($true) {
            $children = @($job.ChildJobs)
            $done     = @($children | Where-Object { $_.State -notin 'NotStarted', 'Running' }).Count
            $running  = @($children | Where-Object { $_.State -eq 'Running' } | Select-Object -First 3 | ForEach-Object { $_.Location })
            Write-Progress -Id 1 -Activity $act `
                -Status ("Шаг 3 из 3: опрошено {0} из {1} | {2:mm\:ss} | сейчас: {3} | Esc — прервать" -f $done, $total, $sw.Elapsed, ($running -join ', ')) `
                -PercentComplete ([int](100 * $done / [math]::Max(1, $total)))
            if ($job.State -notin 'Running', 'NotStarted') { break }
            if (Test-EscPressed) { $cancelled = $true; Stop-Job $job -ErrorAction SilentlyContinue; break }
            Start-Sleep -Milliseconds 400
        }

        $raw = @(Receive-Job $job -ErrorAction SilentlyContinue)

        foreach ($ch in $job.ChildJobs) {
            $c = $script:CompMap[[string]$ch.Location]
            if (-not $c) { continue }
            if ($ch.State -eq 'Completed') { $c.Connected = $true; $c.Error = ''; $okCount++ }
            else {
                $c.Connected = $false
                $reason = $null
                try { $reason = $ch.JobStateInfo.Reason.Message } catch { }
                if (-not $reason) { $reason = if ($ch.State -in 'Stopped', 'NotStarted') { 'Опрос прерван' } else { "Состояние: $($ch.State)" } }
                $c.Error = Limit-Text (($reason -split "`n")[0]) 120
            }
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue

        $list = foreach ($x in $raw) {
            $c = $script:CompMap[[string]$x.Computer]
            if (-not $c) { continue }
            $isMachine = ($x.Source -eq 'Task') -or ($x.Hive -eq 'HKLM')
            $keyName   = if ($x.Source -eq 'Task') { $x.Location + $x.Name } else { $x.Name }
            [pscustomobject]@{
                Computer   = $c.Name
                Type       = $c.Type
                Source     = $x.Source
                SourceName = Get-SourceName $x.Source
                KindName   = $(if ($isMachine) { 'Система' } else { 'Пользователь' })
                Scope      = $x.Scope
                Name       = $x.Name
                Command    = $x.Command
                Detail     = $x.Detail
                Enabled    = [bool]$x.Enabled
                Hive       = $x.Hive
                Location   = $x.Location
                Appr       = $x.Appr
                IdKey      = ('{0}|{1}|{2}|{3}|{4}' -f $c.Name, $x.Source, $x.Hive, $x.Location, $x.Name)
                Key        = ('{0}|{1}|{2}' -f $x.Source, $(if ($isMachine) { 'M' } else { 'U' }), $keyName)
            }
        }
        $script:Items = @($script:Items) + @($list)
    }

    Write-Progress -Id 1 -Activity $act -Completed
    $script:LastScan = Get-Date
    $failed = $new.Count - $okCount
    Write-Log ("Скан [{0}; {1}]: компьютеров {2}, опрошено {3}, ошибок/недоступно {4}, элементов {5}{6}" -f
        (Get-ScanTypeName), $(if ($script:ScanOU) { $script:ScanOU } else { 'весь домен' }),
        $new.Count, $okCount, $failed, @($script:Items | Where-Object { $newSet.ContainsKey($_.Computer) }).Count,
        $(if ($cancelled) { ' (прервано)' } else { '' }))
    Write-Host ''
    Write-Host ("Готово за {0:mm\:ss}{1}. Компьютеров: {2}, опрошено: {3}, недоступно/ошибок: {4}." -f
        $sw.Elapsed, $(if ($cancelled) { ' (прервано пользователем)' } else { '' }), $new.Count, $okCount, $failed) -ForegroundColor Green
    Write-Host 'Список проблемных компьютеров — в разделе «Недоступные».' -ForegroundColor DarkGray
    Wait-Key
}

# --------------------------------- Просмотр ---------------------------------

function Show-Items {
    param([string]$Type, [string]$Title)
    Write-Header $Title
    $comps = @($script:Computers | Where-Object { $_.Type -eq $Type })
    $ok    = @($comps | Where-Object { $_.Connected })
    Write-Host ("Компьютеров: {0}, опрошено: {1}, недоступно: {2}" -f $comps.Count, $ok.Count, ($comps.Count - $ok.Count))
    $items = @(Get-VisibleItems $Type | Sort-Object Computer, SourceName, KindName, Name)
    Write-Host ("Элементов: {0}" -f $items.Count)
    Write-Host ''
    if ($items.Count -eq 0) { Write-Host 'Нет данных. Выполните сканирование (пункт 1).' -ForegroundColor Yellow; Wait-Key; return }

    $fmt = $items | Format-Table -GroupBy Computer -Property `
        @{n='Источник'; e={ $_.SourceName }},
        @{n='Кому'; e={ Limit-Text $_.Scope 22 }},
        @{n='Имя'; e={ Limit-Text $_.Name 34 }},
        @{n='Состояние'; e={ if ($_.Enabled) { 'Вкл' } else { 'ОТКЛ' } }},
        @{n='Команда'; e={ Limit-Text $_.Command 55 }} -AutoSize -Wrap
    try { $fmt | Out-Host -Paging } catch { $fmt | Out-Host }
    Wait-Key
}

function Show-Summary {
    Write-Header 'Сводка: какой элемент автозагрузки на скольких компьютерах'
    $f = Read-Host 'Фильтр по имени или команде (Enter — все)'
    $groups = Get-ItemGroups $f
    if ($groups.Count -eq 0) { Write-Host 'Ничего не найдено.' -ForegroundColor Yellow; Wait-Key; return }
    Show-GroupTable $groups
    Wait-Key
}

function Show-Unreachable {
    Write-Header 'Компьютеры, с которых не удалось получить данные'
    $bad = @($script:Computers | Where-Object { -not $_.Connected })
    if ($bad.Count -eq 0) { Write-Host 'Все компьютеры опрошены.' -ForegroundColor Green }
    else {
        $bad | Sort-Object Type, Name |
            Format-Table Name, Type, @{n='ОС';e={ Limit-Text $_.OS 28 }}, @{n='Причина';e={ Limit-Text $_.Error 60 }} -AutoSize |
            Out-Host
    }
    Wait-Key
}

# ---------------------------------- Действия --------------------------------

function Invoke-StartupAction {
    param([ValidateSet('Enable','Disable','Delete')][string]$Op, $Records)
    $Records = @($Records)
    if ($Records.Count -eq 0) { Write-Host 'Нечего изменять.' -ForegroundColor Yellow; return }

    $title = @{ Enable = 'ВКЛЮЧЕНЫ'; Disable = 'ОТКЛЮЧЕНЫ'; Delete = 'УДАЛЕНЫ' }[$Op]
    $color = if ($Op -eq 'Delete') { 'Red' } else { 'Yellow' }
    Write-Host ''
    Write-Host "Будут $title следующие элементы:" -ForegroundColor $color
    $Records | Sort-Object Computer, SourceName, Name |
        Format-Table Computer, Type, SourceName, @{n='Кому';e={ Limit-Text $_.Scope 22 }}, @{n='Имя';e={ Limit-Text $_.Name 40 }} -AutoSize |
        Out-Host
    if ($Records | Where-Object { $_.Source -eq 'Task' -and $_.Location -like '\Microsoft\*' }) {
        Write-Host 'ВНИМАНИЕ: среди элементов есть системные задания \Microsoft\* — это может повредить Windows!' -ForegroundColor Red
    }
    $cnt = @($Records | Select-Object -ExpandProperty Computer -Unique).Count
    if ($Op -eq 'Delete') {
        $ans = Read-Host ("Удаление необратимо. Элементов: {0}, компьютеров: {1}. Введите YES для подтверждения" -f $Records.Count, $cnt)
        if ($ans -cne 'YES') { Write-Host 'Отменено.' -ForegroundColor Yellow; return }
    } else {
        Write-Host ("Элементов: {0}, компьютеров: {1}. Применить? [Y — да, любая другая — отмена] " -f $Records.Count, $cnt) -NoNewline
        $k = (Read-Key).ToUpper(); Write-Host ''
        if ($k -notin 'Y', 'Н') { Write-Host 'Отменено.' -ForegroundColor Yellow; return }
    }

    $targets = @($Records | Select-Object -ExpandProperty Computer -Unique)
    $slim    = @($Records | Select-Object IdKey, Computer, Source, Hive, Location, Appr, Name)
    Write-Host 'Выполняю на удалённых компьютерах...' -ForegroundColor Cyan
    $opt  = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000
    $errs = $null
    $res  = Invoke-Command -ComputerName $targets -ScriptBlock $script:RemoteBlock `
            -ArgumentList $Op, $slim -SessionOption $opt -ThrottleLimit 32 `
            -ErrorAction SilentlyContinue -ErrorVariable errs

    $byId = @{}
    foreach ($r in $res) { $byId[[string]$r.IdKey] = $r }
    $connErr = @{}
    foreach ($e in $errs) {
        $pc = $null
        if ($e.TargetObject -is [string]) { $pc = $e.TargetObject }
        if (-not $pc) { try { $pc = [string]$e.OriginInfo.PSComputerName } catch { } }
        if ($pc) { $connErr[$pc] = (($e.Exception.Message) -split "`n")[0] }
    }

    $done = @(); $fail = 0
    foreach ($rec in $Records) {
        $r = $byId[$rec.IdKey]
        $label = '{0}: [{1}] {2}' -f $rec.Computer, $rec.SourceName, $rec.Name
        if ($r -and $r.Ok) {
            Write-Host "  [OK]  $label" -ForegroundColor Green
            Write-Log ("{0} {1} | {2}" -f $Op.ToUpper(), $label, $rec.Command)
            $done += $rec
        } else {
            $fail++
            $msg = if ($r) { $r.Message } elseif ($connErr.ContainsKey($rec.Computer)) { $connErr[$rec.Computer] } else { 'нет ответа' }
            Write-Host "  [ERR] $label — $msg" -ForegroundColor Red
            Write-Log ("ОШИБКА {0} {1} — {2}" -f $Op.ToUpper(), $label, $msg)
        }
    }
    if ($done.Count -gt 0) {
        switch ($Op) {
            'Delete'  { $script:Items = @($script:Items | Where-Object { $done -notcontains $_ }) }
            'Enable'  { foreach ($d in $done) { $d.Enabled = $true } }
            'Disable' { foreach ($d in $done) { $d.Enabled = $false } }
        }
    }
    Write-Host ''
    Write-Host ("Успешно: {0}, ошибок: {1}. Лог: {2}" -f $done.Count, $fail, $LogPath) -ForegroundColor Cyan
}

function Test-GridView {
    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-Host 'Out-GridView недоступен (Server Core или нет компонента ISE/GraphicalTools).' -ForegroundColor Red
        return $false
    }
    $true
}

function Invoke-ByName {
    param([ValidateSet('Enable','Disable','Delete')][string]$Op)
    $names = @{ Enable = 'Включение'; Disable = 'Отключение'; Delete = 'Удаление' }
    Write-Header ("{0} элемента автозагрузки по имени" -f $names[$Op])
    $f = Read-Host 'Фильтр по имени или команде (Enter — все)'
    $groups = Get-ItemGroups $f
    if ($groups.Count -eq 0) { Write-Host 'Ничего не найдено.' -ForegroundColor Yellow; Wait-Key; return }
    Show-GroupTable $groups

    $sel = Read-Host 'Номера элементов через запятую (Enter — отмена)'
    if (-not $sel) { return }
    $idx = @($sel -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    $records = @()
    foreach ($n in $idx) {
        if ($n -ge 1 -and $n -le $groups.Count) { $records += @($groups[$n - 1].Group) }
    }
    if ($records.Count -eq 0) { Write-Host 'Неверный выбор.' -ForegroundColor Yellow; Wait-Key; return }

    Write-Host ''
    Write-Host 'Область применения:' -ForegroundColor Cyan
    Write-Host '  [A] все компьютеры, где есть элемент'
    Write-Host '  [C] только компьютеры пользователей'
    Write-Host '  [S] только серверы и ВМ'
    Write-Host '  [G] выбрать компьютеры вручную (окно Out-GridView)'
    Write-Host '  [любая другая] отмена'
    $k = (Read-Key).ToUpper()
    switch ($k) {
        { $_ -in 'A','Ф' } { $target = $records }
        { $_ -in 'C','С' } { $target = @($records | Where-Object { $_.Type -eq 'Client' }) }
        { $_ -in 'S','Ы' } { $target = @($records | Where-Object { $_.Type -eq 'Server' }) }
        { $_ -in 'G','П' } {
            if (-not (Test-GridView)) { Wait-Key; return }
            $target = @($records | Sort-Object Computer | Out-GridView -PassThru `
                        -Title 'Выделите строки (Ctrl/Shift), затем OK')
        }
        default { Write-Host 'Отменено.' -ForegroundColor Yellow; Wait-Key; return }
    }
    # не трогаем элементы, которые уже в нужном состоянии
    if ($Op -eq 'Disable') { $target = @($target | Where-Object { $_.Enabled }) }
    if ($Op -eq 'Enable')  { $target = @($target | Where-Object { -not $_.Enabled }) }
    Invoke-StartupAction -Op $Op -Records $target
    Wait-Key
}

function Invoke-ByGrid {
    Write-Header 'Выбор отдельных строк (компьютер + элемент)'
    if (-not (Test-GridView)) { Wait-Key; return }
    $items = @(Get-VisibleItems | Sort-Object Type, Computer, SourceName, Name)
    if ($items.Count -eq 0) { Write-Host 'Нет данных. Выполните сканирование.' -ForegroundColor Yellow; Wait-Key; return }
    Write-Host 'Откроется окно: отметьте строки (Ctrl/Shift), нажмите OK.' -ForegroundColor Cyan
    $picked = @($items | Select-Object * | Out-GridView -PassThru -Title 'Выберите элементы автозагрузки')
    if ($picked.Count -eq 0) { return }
    # Out-GridView возвращает копии? сопоставляем с оригиналами по IdKey
    $ids = @{}; foreach ($p in $picked) { $ids[$p.IdKey] = $true }
    $records = @($items | Where-Object { $ids.ContainsKey($_.IdKey) })

    Write-Host ''
    Write-Host ("Выбрано: {0}. Действие: [E] включить  [D] отключить  [X] удалить  [другая] отмена" -f $records.Count) -ForegroundColor Cyan
    switch ((Read-Key).ToUpper()) {
        { $_ -in 'E','У' } { Invoke-StartupAction -Op Enable  -Records $records }
        { $_ -in 'D','В' } { Invoke-StartupAction -Op Disable -Records $records }
        { $_ -in 'X','Ч' } { Invoke-StartupAction -Op Delete  -Records $records }
        default            { Write-Host 'Отменено.' -ForegroundColor Yellow }
    }
    Wait-Key
}

# --------------------------------- Экспорт ----------------------------------

function Export-Data {
    Write-Header 'Экспорт в CSV'
    if ($script:Items.Count -eq 0) { Write-Host 'Нет данных.' -ForegroundColor Yellow; Wait-Key; return }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $f1 = Join-Path $LogBase "Startup_$stamp.csv"
    $f2 = Join-Path $LogBase "StartupComputers_$stamp.csv"
    $script:Items | Select-Object Computer, Type, SourceName, KindName, Scope, Name, Enabled, Detail, Location, Command |
        Export-Csv $f1 -NoTypeInformation -Encoding UTF8
    $script:Computers | Select-Object Name, Type, OS, Online, Connected, Error |
        Export-Csv $f2 -NoTypeInformation -Encoding UTF8
    Write-Host "Сохранено:`n  $f1`n  $f2" -ForegroundColor Green
    Wait-Key
}

# ----------------------------------- Меню -----------------------------------

function Show-MainMenu {
    Write-Header "Автозагрузка компьютеров домена $Domain"
    $cl = @($script:Computers | Where-Object { $_.Type -eq 'Client' })
    $sv = @($script:Computers | Where-Object { $_.Type -eq 'Server' })
    $on = @($script:Computers | Where-Object { $_.Connected })
    if ($script:Computers.Count -eq 0) {
        Write-Host '  Данных пока нет. Задайте параметры (пункты 2 и 3) и запустите сканирование (пункт 1).' -ForegroundColor Yellow
    } else {
        $vis = @(Get-VisibleItems)
        Write-Host ("  Просканировано компьютеров: {0} (клиенты: {1}, серверы/ВМ: {2}), опрошено успешно: {3}" -f
                    $script:Computers.Count, $cl.Count, $sv.Count, $on.Count)
        Write-Host ("  Элементов автозагрузки: {0} (с учётом фильтров: {1}, отключённых: {2})" -f
                    $script:Items.Count, $vis.Count, @($vis | Where-Object { -not $_.Enabled }).Count)
        if ($script:LastScan) { Write-Host ("  Последнее сканирование: {0:dd.MM.yyyy HH:mm:ss}" -f $script:LastScan) }
    }
    Write-Host ''
    Write-Host '  Сканирование' -ForegroundColor Cyan
    Write-Host '   1) Запустить сканирование с текущими параметрами' -ForegroundColor Green
    Write-Host ("   2) Тип компьютеров: [{0}]  (нажмите, чтобы переключить)" -f (Get-ScanTypeName))
    Write-Host ("   3) Область (OU): [{0}]" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host '   C) Очистить результаты'
    Write-Host ''
    Write-Host '  Просмотр' -ForegroundColor Cyan
    Write-Host '   4) Автозагрузка: компьютеры пользователей'
    Write-Host '   5) Автозагрузка: серверы и виртуальные машины'
    Write-Host '   6) Сводка (имя → на скольких ПК)'
    Write-Host '   U) Недоступные компьютеры'
    Write-Host ''
    Write-Host '  Изменение' -ForegroundColor Cyan
    Write-Host '   7) Отключить по имени (все / выборочно)' -ForegroundColor Yellow
    Write-Host '   8) Включить по имени (все / выборочно)' -ForegroundColor Yellow
    Write-Host '   9) Удалить по имени (все / выборочно)' -ForegroundColor Red
    Write-Host '   G) Выбрать строки (Out-GridView) и применить действие'
    Write-Host ''
    Write-Host '  Прочее' -ForegroundColor Cyan
    Write-Host ("   T) Задания планировщика (вход/загрузка): {0}" -f $(if ($script:ShowTasks) { 'показаны' } else { 'скрыты' }))
    Write-Host ("   M) Системные задания \Microsoft\*: {0}" -f $(if ($script:ShowMS) { 'показаны' } else { 'скрыты' }))
    Write-Host '   E) Экспорт в CSV'
    Write-Host '   0) Выход'
    Write-Host ''
    Write-Host '  Выберите пункт: ' -NoNewline
}

# Программа сначала показывает меню, сканирование запускается только по пункту 1.
while ($true) {
    Show-MainMenu
    $key = (Read-Key).ToUpper()
    switch ($key) {
        '1' { Invoke-Scan }
        '2' { Switch-ScanType }
        '3' { Select-ScanOU }
        '4' { Show-Items -Type 'Client' -Title 'Автозагрузка: компьютеры пользователей' }
        '5' { Show-Items -Type 'Server' -Title 'Автозагрузка: серверы и виртуальные машины' }
        '6' { Show-Summary }
        '7' { Invoke-ByName -Op Disable }
        '8' { Invoke-ByName -Op Enable }
        '9' { Invoke-ByName -Op Delete }
        { $_ -in 'G','П' } { Invoke-ByGrid }
        { $_ -in 'U','Г' } { Show-Unreachable }
        { $_ -in 'T','Е' } { $script:ShowTasks = -not $script:ShowTasks }
        { $_ -in 'M','Ь' } { $script:ShowMS    = -not $script:ShowMS }
        { $_ -in 'E','У' } { Export-Data }
        { $_ -in 'C','С' } { Clear-Results }
        '0' { Clear-Host; return }
    }
}
