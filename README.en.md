# AD Startup Manager

An interactive PowerShell console (`sconfig`-style menu) to **view, enable, disable and delete startup (autorun) entries** on all computers of an Active Directory domain: workstations, servers and virtual machines.

> [Русская версия](README.md)

## What counts as startup

| Source | What is checked |
|--------|-----------------|
| Registry `Run` | `HKLM\...\Run`, `HKLM\...\WOW6432Node\...\Run` (x86) and `HKU\<SID>\...\Run` for **all user profiles** (unloaded `NTUSER.DAT` files are loaded temporarily) |
| Startup folders | the common one (`ProgramData`) and every profile's folder |
| Task Scheduler | tasks with a logon / boot trigger (system `\Microsoft\*` tasks hidden by default) |

Not covered: `RunOnce`, services, drivers, `Winlogon`/`Shell`, WMI subscriptions and other persistence mechanisms.

## Features

- **Enable, disable and delete** entries. For registry and folder items, enable/disable works like Task Manager (`StartupApproved` keys); for tasks it uses `Enable/Disable-ScheduledTask`.
- Separate tables for **user computers** and **servers / VMs** (by AD `OperatingSystem`).
- Choose what to scan: all / user computers / servers, or **individual OUs** (including child OUs). Results of several scans accumulate.
- **Progress bar** and `Esc` to abort.
- Summary view "entry → how many computers", including how many are disabled.
- Actions **by name** on all or selected computers; per-row selection in `Out-GridView`.
- `YES` confirmation for deletion, a log (the command of a deleted entry is recorded), CSV export, unreachable-computer list.

## Requirements

- Windows PowerShell 5.1 (PowerShell 7 has not been tested).
- **ActiveDirectory** module (RSAT).
- Administrator rights on the target computers.
- **WinRM (TCP 5985)** enabled on the targets: the script runs on them through `Invoke-Command`. There is no DCOM fallback.
- `Out-GridView` is needed for manual row selection.

## Quick start

```powershell
git clone https://github.com/llex666/ad-startup-manager.git
cd ad-startup-manager

powershell -ExecutionPolicy Bypass -File .\Manage-DomainStartup.ps1
# or
.\Manage-DomainStartup.ps1 -Domain corp.example.com -StaleDays 60
```

The program **shows the menu first**; scanning starts with item `1`.

## Parameters

| Parameter     | Default                    | Description                                                   |
|---------------|----------------------------|---------------------------------------------------------------|
| `-Domain`     | `$env:USERDNSDOMAIN`       | DNS name of the AD domain                                     |
| `-StaleDays`  | `90`                       | Skip computers that have not logged on to the domain for N days |

## Menu

The menu is displayed in Russian (see the Russian README for a sample). Items: scan (1), computer type (2), OU (3), clear (C), clients (4), servers (5), summary (6), unreachable (U), disable by name (7), enable by name (8), delete by name (9), pick rows in Out-GridView (G), toggle scheduler tasks (T), toggle system tasks (M), CSV export (E), exit (0).

## How it works

1. The computer list comes from AD, filtered by type, OU and `-StaleDays`.
2. Port 5985 is probed in parallel (in chunks of 100).
3. A code block is sent to reachable computers with `Invoke-Command -AsJob` (up to 32 at once); progress is based on finished child jobs.
4. On each target the block reads the registry, Startup folders and Task Scheduler, and edits the same sources when asked.
5. User profiles that are not loaded are mounted temporarily with `reg load` and unloaded afterwards.

## Safety and limitations

- **Deletion is irreversible.** Test on a pilot OU. The command of a deleted entry is written to the log so it can be restored manually.
- The log (`DomainStartupManager.log`) and CSV files contain computer names, user names and command lines. Do not publish them (they are in `.gitignore`).
- Profiles whose `NTUSER.DAT` is locked (e.g. while the user is signing in) may be skipped or return an error.
- Computers without WinRM are listed under "Unreachable".
- Use at your own risk (see the license).

## Related projects

- [AD Scheduled Tasks Manager](https://github.com/llex666/ad-tasks-manager): scheduled tasks.
- [AD Software Manager](https://github.com/llex666/ad-software-manager): installed software.

## License

[MIT](LICENSE)
