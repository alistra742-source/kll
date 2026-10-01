# Signing the driver — the real chain

Kernel-mode drivers cannot be signed with an ordinary code-signing certificate.
Windows loads a kernel driver only if it carries a signature from Microsoft's
own driver-signing chain. The route to that is **attestation signing**, and it
has a hard gate before you even get to upload anything.

## What you actually need (in order)

| Step | What | Cost / effort |
|---|---|---|
| 1 | **An EV code-signing certificate** | ~$200–600/yr, requires a verified legal entity (company or sole trader with papers) |
| 2 | **A Partner Center account** with that EV cert associated | free, but the EV association is what gates submissions |
| 3 | **A built driver package** — a CAB with `.inf` + `.sys` + `.cat` | this repo builds it (`package_driver.bat`) |
| 4 | **Submit for attestation signing** | free; Microsoft signs it |
| 5 | Download the Microsoft-signed `.sys` | loads on retail Windows, no test-signing |

Microsoft states the gate plainly: *"To submit binaries for attestation signing,
your Hardware Dev Center dashboard account must have at least one EV certificate
associated with it."* There is no free shortcut around step 1.

## Why an EV cert specifically

Attestation signing used to accept a normal cert. It no longer does — as of the
current requirements, the dashboard account must have an EV certificate. That is
why the certificate is the expensive, slow part, and why the code is the easy
part.

## The build

```bat
cd driver
build_driver.bat      REM -> nightrelay.sys
package_driver.bat    REM -> nightrelay.cab   (inf + sys + cat)
```

`package_driver.bat` runs the build, generates the catalog with `Inf2Cat`, and
packs everything with `makecab`. The result, `nightrelay.cab`, is the file you
upload.

## The submission

1. Sign in at **https://partner.microsoft.com/en-us/dashboard/hardware/** with
   the Microsoft account that owns the EV-associated dashboard.
2. **Submit new driver** → choose **attestation signing** (not WHQL/HLK).
3. Upload `nightrelay.cab`.
4. Select the target OS list (Windows 10/11 x64; the driver is x64 only).
5. Attestation signing does **not** run HLK tests — it signs the driver as-is,
   which is the whole point of the attestation path.
6. When it returns, the download contains a Microsoft-signed `nightrelay.sys`.
   Ship *that* one.

## What attestation signing does and does not do

- **Does:** makes the `.sys` load on retail Windows without `testsigning` or a
  self-signed cert. This is what you distribute to buyers.
- **Does not:** make the driver invisible to anti-cheat, or whitelist it
  anywhere. Anti-cheat detects behaviour, not signatures. A Microsoft signature
  means "Windows will load this"; it means nothing about what the driver does.

## Until then (development)

Loading an unsigned driver needs test signing, and that is **only ever done in a
throwaway VM** — see `README.md`. Never run `bcdedit /set testsigning on` on your
real machine; it weakens driver enforcement for every driver, permanently, and is
exactly the damage the VM exists to avoid.
