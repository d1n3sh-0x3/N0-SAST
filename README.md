# NO-SAST

Android APK scanner that screenshots every finding with the vulnerable line
boxed in red.

One file, no decompiler, no device. The binary `AndroidManifest.xml`, the
layout resources, the DEX string tables and the APK signing block are all
parsed by the script itself.

```
python nosast.py app.apk
python nosast.py                      # prompts for the APK path
python nosast.py app.apk -o C:\reports
```

Requires Python 3.8+ and Pillow:

```
pip install -r requirements.txt
```

## Output

```
<AppName>/
  Exported_Activities/
      01_AndroidManifest_L169.png
  Excessive_Permissions/
      01_AndroidManifest_L57-126_x6.png      one image, every flagged row boxed
  Tapjacking_Overlay_Touch_Hijacking/
      01_tapjacking-check_L5-9.png           both NOT FOUND rows boxed
  SQL_Queries_Recovered_By_Reverse_Engineering/
      01_sql-queries-recovered_L8.png
  Secured/
      Backup_Disabled/
      Tapjacking_Protection_Present/
      APK_Signature_Scheme_v3_Present/
```

Directory per app, directory per issue, one PNG per location. Each PNG is the
code window and nothing else: a red rectangle around the offending row, every
surrounding line left exactly as it is. Controls that pass land under
`Secured/` with a green rectangle.

Options: `--context N` lines around the highlight (default 7), `--max-shots N`
images per issue (default 12).

## Checks

| | |
|---|---|
| 001 | Insecure Minimum SDK (minSdk < 28) |
| 002 | targetSdkVersion not current |
| 003 | Backup data exposure (allowBackup) |
| 004 | Debuggable release build |
| 005 | Cleartext traffic permitted |
| 006 | Exported activities |
| 007 | Exported services |
| 008 | Exported content providers |
| 009 | Insecure external storage permissions |
| 010 | Excessive / dangerous permissions |
| 011 | Unprotected broadcast receivers |
| 012 | Task hijacking via taskAffinity |
| 013 | Hardcoded credentials in manifest metadata |
| 014 | Unprotected file provider |
| 015 | Custom permission misuse |
| 016 | Excessive exported activities |
| 017 | Implicit broadcast handling |
| 018 | Unencrypted unfiltered backups |
| 019 | Insecure intent and deep link handling |
| 020 | maxSdkVersion declared |
| 021 | Tapjacking - both `filterTouchesWhenObscured` and `setFilterTouchesWhenObscured` are searched; if either exists it is filed under `Secured/` |
| 022 | Missing APK Signature Scheme v3 |
| 023 | Missing APK Signature Scheme v4 |
| 024 | Weak signing (v1-only / Janus, debug certificate) |
| 025 | SQL queries recovered by reverse engineering |

Signature schemes are read from the APK Signing Block directly
(`0x7109871a` v2, `0xf05368c0` v3, `0x1b93ad61` v3.1, and the `.idsig`
sidecar for v4).

## Notes

- `protectionLevel` is decoded from its integer bitmask, so signature-level
  permissions are not misreported as weak.
- A non-exported `FileProvider` with `grantUriPermissions="true"` is not
  flagged - that is the recommended configuration.
- Release builds shorten resource paths to `res/0C.xml`, so layouts are
  identified by the tags inside them rather than by filename.

---

https://github.com/d1n3sh-0x3/
https://www.linkedin.com/in/dinesh-goud
