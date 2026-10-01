# NightRelay driver — build and test

This directory is the piece `nr/manualmap.py` measured the need for. The client
grants `VM_READ | VM_WRITE | VM_OPERATION | CREATE_THREAD`, the image gets
written, and the remote thread returns `0xC000071C` — execution is the line, and
a kernel driver is what crosses it.

The rule for everything below: **the driver never loads on your real PC.** It is
built there and loaded only inside a throwaway VM you can delete in one command.
A `.sys` sitting in a folder does nothing; it only becomes code when the kernel
loading it is the guest's.

---

## 0. What you need

| Tool | Where | Why |
|---|---|---|
| Visual Studio Build Tools, C++ x64 workload | VS Installer | compiles the `.sys` |
| Windows Driver Kit (WDK) | VS Installer → Individual components | kernel headers + libs |
| Oracle VirtualBox | already installed | the sandbox |
| A Windows 10/11 x64 ISO | Microsoft | the guest OS |

`build_driver.bat` finds VS and the WDK on its own, the same way
`payload\build_payload.bat` does.

---

## 1. Build (on the host, harmless)

```bat
cd driver
build_driver.bat
```

Output: `driver\nightrelay.sys` (compiles `nightrelay_drv.c` + `nr_stealth.c`).
Compiling is inert — nothing runs until a kernel loads it. If the link step
complains about a missing library, add it with `/DEFAULTLIB:<name>.lib`; the set
in the script is the standard WDM one.

Build the usermode client too (it drives the driver from inside the guest):

```bat
cl /nologo /EHsc /O2 /W4 /std:c++17 nr_client.cpp /link ntdll.lib
```

## Stealth (what the hardening actually does)

The public detection surface for mapped/loaded drivers is well documented, and
the hardening here targets it directly rather than claiming invisibility:

| Trace | What it is | What this driver does |
|---|---|---|
| Symbolic link | a walkable name in the object namespace | **none created** — the client opens the device object path directly |
| Device-name literal | a greppable string in the `.sys` | stored XOR-encoded, decoded in memory only |
| `MmUnloadedDrivers` | ring of the last unloaded drivers, by name | matching row zeroed on next load (`nr_stealth.c`) |
| `PsLoadedModuleList` | the loaded-module list every enumerator walks | our entry unlinked (DKOM), bounds-checked |
| `PiDDBCacheTable` | driver-database cache, name + timestamp | routine is a named stub with the recipe inline — the offset is build-specific and guessing it bugchecks the box |
| Target handle | what a handle-enumerating anti-tamper strips | **none opened** — attach holds an `EPROCESS` ref, RW goes through `MmCopyVirtualMemory` |

Two honest caveats, stated because they matter more than the table:

- **No driver is "unbannable."** Anti-cheats scan physical memory for MSVC
  import wrappers (`FF 25` gadgets) sitting in pages no module owns. A driver
  loaded as a normal service image does not have that problem; a *manually
  mapped* one does, and the fix is the mapper, not the driver.
- **Every offset above that is a `FILL` fails closed.** A wrong value refuses
  rather than scribbles. That is deliberate: a stealth pass that crashes the
  guest is worse than one that does nothing.

---

## 2. Make the VM (once)

```powershell
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VM   = "NightRelaySandbox"

& $VBox createvm --name $VM --ostype Windows11_64 --register
& $VBox modifyvm $VM --memory 4096 --cpus 2 --vram 128 --firmware efi
& $VBox modifyvm $VM --nic1 nat
# attach your Windows ISO, then install Windows in the guest:
& $VBox storagectl $VM --name "IDE" --add ide
& $VBox storageattach $VM --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium "C:\path\to\Win11.iso"
```

Install Windows in the guest normally. **Set network to host-only or off inside
the guest if you want zero contact with anything.** Nothing here needs the
internet.

### Turn on test signing in the guest only

An unsigned driver will not load otherwise. Inside the guest, as admin:

```bat
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

Leave the host's boot configuration alone. `testsigning on` on your real machine
weakens it for every driver, forever — that is exactly the damage this whole
setup exists to avoid.

---

## 3. Freeze a clean snapshot

With the guest freshly installed, tested-signed, and rebooted:

```powershell
& $VBox snapshot $VM take "clean" --description "bare windows, no driver"
```

This is the point you always come back to. Every test starts here and ends here.

---

## 4. Run the test

1. Copy `nightrelay.sys` into the guest. Either a VirtualBox shared folder
   (`Devices → Shared Folders`) or `VBoxManage guestcontrol copyto`:

   ```powershell
   & $VBox guestcontrol $VM copyto --target-directory "C:\nr" "nightrelay.sys" --username <guestuser> --password <pw>
   ```

2. In the guest, register and start it as a kernel service (no INF needed for a
   test load):

   ```bat
   sc create NightRelay type= kernel binPath= C:\nr\nightrelay.sys
   sc start NightRelay
   ```

   A clean start shows `STATE : 4 RUNNING`. If it fails, `sc query NightRelay`
   plus `Event Viewer → Windows Logs → System` names the reason — usually a
   missing dependency or signing still off.

3. Drive it from the guest. Create the device handle and issue the IOCTLs; the
   usermode side of the interface is `nightrelay.h`.

4. Point it at a **test process inside the guest** first — notepad, or a
   throwaway program the driver reads and writes. Confirm attach and
   read/write before it ever looks at Roblox.

   The client (`nr_client.exe`) exercises it from inside the guest: attach,
   read, write, module base, elevate, against a process you control first.

6. When you are done — **or the moment anything looks wrong** — kill the guest
   and restore:

   ```powershell
   & $VBox controlvm $VM poweroff
   & $VBox snapshot $VM restore "clean"
   ```

   The guest is now bit-for-bit the state from step 3. Any damage, corruption,
   or stuck driver state is gone. Your host never saw any of it.

---

## 5. The safety rules, plainly

- The host only ever *compiles*. The guest only ever *loads*.
- One clean snapshot before the first test. Restore after every session.
- Test against a process you control inside the guest first, Roblox second.
- A kernel bug is a bug in the guest kernel, which is what the snapshot is for.
  A bug on the host kernel is your real machine, which is why the driver never
  gets there.
- If you want zero contact with anything at all, run the guest with its NIC
  disconnected.

---

## 6. What is still a `FILL`

Two things are deliberately marked in `nightrelay_drv.c` because they move per
OS build and guessing them is worse than naming them:

- `OFF_EPROCESS_TOKEN` — read it from `WinDbg → dt nt!_EPROCESS Token` against
  the exact guest build. `NrElevate` fails closed if it is wrong, so a bad value
  refuses rather than corrupts.
- `NrStripHandle` — not needed for the core path (no handle is opened on the
  target), kept as a named hook with the recipe inline.

Everything else — attach, read, write, module-base walk — carries no fixed
address and works across builds.
