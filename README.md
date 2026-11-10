# 2n-fw-update

Firmware update for one or many 2N IP intercoms (with or without camera) over the 2N HTTP API.
Runs on stock Windows PowerShell 5.1 or PowerShell 7 - nothing to install.

```powershell
.\2n-fw-update.ps1 C:\fw\verso.bin 192.168.1.20 -DryRun            # read-only: model, version, login check
.\2n-fw-update.ps1 C:\fw\verso.bin 192.168.1.20,192.168.1.21       # one or many devices
.\2n-fw-update.ps1 C:\fw\verso.bin -DeviceFile doors.txt -Yes      # list from file, no prompt
Get-Help .\2n-fw-update.ps1 -Full                                  # all options
```

Per device: read model + running version, check the login, upload the file, apply, wait for the restart,
confirm the new version. Devices run in parallel (`-Parallel`, default 4); a result table is printed at
the end and the exit code is 0 only when every device runs the new version.

- Device side: Services > HTTP API > System API enabled, account with System Control access.
- Login: `-Credential`, or env `TWON_USER` / `TWON_PASS`, otherwise the script asks.
- HTTPS by default, certificate not checked (2N ships a self-signed one); `-VerifyCertificate` checks it,
  `-Http` uses plain HTTP.
- A downgrade or a device already on that version is skipped (`-AllowDowngrade`, `-Force` to override).
- Firmware is per model family: a device of another model refuses the file and stays untouched.
- If "running scripts is disabled": `powershell -ExecutionPolicy Bypass -File .\2n-fw-update.ps1 ...`

API reference: 2N HTTP API manual, sections 5.2.1-5.2.3 (`api/firmware`, `apply`, `reject`).

`2n-mock-device.py` is a local stand-in for a 2N device, used to test the script without hardware.
Status: tested against the mock only, not yet on a real 2N device.
