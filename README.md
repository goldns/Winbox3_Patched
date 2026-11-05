# WinBox 3.43.0.1

**Bugs or feature requests? Message me on Telegram: [@kamgoldns](https://t.me/kamgoldns).**

English | [Русский](README-RU.md)

Classic WinBox 3 for Windows x64, updated to work with newer RouterOS releases. The familiar interface, with fixes for CMR, missing buttons and newer field types.

Start **[winbox64.v3.43_patched.exe](winbox64.v3.43_patched.exe)** and connect as usual. No installation or Python required to run it.

## What's included

| Patch | Changes |
| --- | --- |
| `patch_mark99i_1` | Connections to newer RouterOS and handling of unsupported UI elements |
| `patch_mark99i_2` | Embedded icons and startup extraction |
| `patch_mark99i_3` | Startup stack alignment, Format Drive protection and the Switch icon |
| `patch_mark99i_4` | Editing `bytes` and `bigbytes` fields |
| `patch_mark99i_5` | CMR models, Dashboard guards and icons |
| `patch_mark99i_6` | WiFi realms, Container ENV, zoom, large counters and other interface fixes |
| `patch_mark99i_7` | Adapted **Settings → Swap title order**, with a saved preference |
| `patch_1-core` | Configurable application version and `bigbytes` overflow protection |
| `patch_2-cmr` | Restored Packages and Container buttons; fixed a CMR Dashboard crash |
| `patch_3-bigfixedpoint` | Display of 64-bit fixed-point values, including NTP statistics |
| `patch_4-biginterval` | Display of 64-bit durations, including Flat Snoop's BSS On Time |
| `patch_5-bignumberrange` | Viewing and editing Range in **Routing → Filters → Num Set** |
| `patch_6-u32vector` | Device IDs passed to CMR Pair/Upgrade dialogs |
| `patch_7-tags` | Labels, Port Labels and Order editors with separate mode and name controls |
| `patch_8-bargraph` | Access Points / Stations bar charts, paging and Dashboard scrolling |
| `patch_9-topolayout` | CMR topology: nodes, links, zoom, pan and saved node positions |
| `patch_diagnostics` | Optional resource and skipped-field dumps |

Range accepts a number (`55`) or an unsigned 64-bit range (`5-55`). Labels and Port Labels support neutral, `+` and `−` modes; Order supports neutral and `−`. Pair/Upgrade opens a separate dialog for each device.

In **CMR Topology**, drag a node and release it to save its position. Wait for `Saved`; the position is kept when you reopen the map. Drag empty space to pan, use the wheel to zoom, or click **Fit**. **Esc** cancels a drag before release. Coordinates save immediately: Apply is not needed, and Cancel does not undo a position already saved.

**Settings → Swap title order** changes the order of the device identity and connection details in the window title. The choice is stored in `winboxpatch-title.dat` in the WinBox profile folder.

## Build it yourself

You need **Python 3.10+**, [patch_winbox.py](patch_winbox.py) and [the original WinBox 3.43 x64](winbox64.v3.43_orig.exe) in the same folder:

```powershell
python .\patch_winbox.py
```

This creates `winbox64.v3.43_patched.exe`. Everything is embedded in the script; there are no packages or compilers to install. An existing patched EXE is replaced automatically. The original is preserved.

The patcher checks the official original's SHA-256, patch locations and file sizes. It does not require fixed checksums for intermediate or patched builds. To keep another copy, use `--output another.exe`.

The application version is set near the top of the script:

```python
WINBOX_VERSION = "3.43.0.1"
```

Use `A.B.C.D`, with each number from 0 to 65535 and no more than 11 characters in total. Rebuilding updates the window titles and Windows file properties. Patcher version: **1.0.0**.

## Diagnostics

For bug reports, you can build a separate diagnostic EXE:

```powershell
python .\patch_winbox.py --dump-skipped-fields
.\winbox64.v3.43_diagnostic.exe
```

Connect and open the window you want to investigate. Downloaded resources and `skipped-fields-<PID>.tsv` are saved in **`winbox-dump` next to the EXE**. The TSV records skipped-field descriptions, not entered values. The regular build writes no dumps.

## Credits

Based on [mark99i/WinboxPatch](https://github.com/mark99i/WinboxPatch): patches v1–v6 from [84a58a6](https://github.com/mark99i/WinboxPatch/tree/84a58a62d6e623008e7092607041caea1b7ac540), plus the adapted title-order feature from [v7](https://github.com/mark99i/WinboxPatch/commit/af2b242c9747ff78020f237281a816792455a037). ESR interface improvements are credited to **teslasystems**.

This is an unofficial modification of MikroTik WinBox.
