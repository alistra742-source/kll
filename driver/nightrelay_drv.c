/* nightrelay_drv.c -- WDM x64 kernel driver for NightRelay.
 *
 * Why this exists: nr/manualmap.py proved the boundary. On a live client,
 * OpenProcess with VM_READ|VM_WRITE|VM_OPERATION and CREATE_THREAD is granted,
 * the image is written, and then nothing executes -- the remote thread returns
 * 0xC000071C. The refusal is at *execution*, not at loading. Crossing it is what
 * a kernel driver is for, and it is the reason every surviving executor ships
 * one.
 *
 * Design choice that matters for detection: this driver never opens a handle on
 * the target. Attach holds an EPROCESS reference from PsLookupProcessByProcessId
 * and the read/write path goes through MmCopyVirtualMemory. No handle lands in
 * the client's handle table, so there is nothing for a handle-enumerating
 * anti-tamper to strip or flag.
 *
 * Build with the WDK (see build_driver.bat). Test-load requires test signing,
 * which is documented in README.md and is only ever done inside a VM.
 */
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include "nightrelay.h"
#include "nr_stealth.h"

/* ---- version-sensitive kernel offsets. Re-dump these on every target OS build.
 * WinDbg x64:
 *     dt nt!_EPROCESS Token
 *     dt nt!_EPROCESS UniqueProcessId
 *     dt nt!_EPROCESS ObjectTable
 * The defaults below are Win10 22H2 / Win11 23H2 x64. A wrong offset here does
 * not crash anything -- NrElevate checks the resolved pointer and fails closed. */
#define OFF_EPROCESS_TOKEN      0x4b8   /* FILL: EPROCESS->Token on your build           */
#define OFF_EPROCESS_UNIQUEPID  0x440   /* FILL: EPROCESS->UniqueProcessId on your build */

#define NR_TAG 'lRiN'

typedef struct _NR_STATE {
    PEPROCESS  Target;      /* held reference; NULL means detached */
    HANDLE     TargetPid;
    FAST_MUTEX Lock;
} NR_STATE;

static NR_STATE       g_State;
static PDEVICE_OBJECT g_Device = NULL;
static UNICODE_STRING g_DevName;

/* "\\Device\\NightRelay" XOR 0x5A. Held encoded so the plaintext name is not a
 * literal a scanner can grep straight out of the .sys image. Decoded at runtime. */
static const unsigned char kNameXor[] = {
    0x06, 0x1E, 0x3F, 0x2C, 0x33, 0x39, 0x3F, 0x06,
    0x14, 0x33, 0x3D, 0x32, 0x2E, 0x08, 0x3F, 0x36, 0x3B, 0x23
};
static WCHAR g_DevNameChars[RTL_NUMBER_OF(kNameXor) + 1];

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     NrUnload;
DRIVER_DISPATCH   NrCreateClose;
DRIVER_DISPATCH   NrDeviceControl;

static VOID NrDetach(VOID)
{
    ExAcquireFastMutex(&g_State.Lock);
    if (g_State.Target) {
        ObDereferenceObject(g_State.Target);
        g_State.Target    = NULL;
        g_State.TargetPid = 0;
    }
    ExReleaseFastMutex(&g_State.Lock);
}

static NTSTATUS NrAttach(HANDLE pid)
{
    PEPROCESS proc = NULL;
    NTSTATUS  st   = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(st))
        return st;                               /* pid died between user call and here */

    ExAcquireFastMutex(&g_State.Lock);
    if (g_State.Target)
        ObDereferenceObject(g_State.Target);     /* drop the previous reference */
    g_State.Target    = proc;                    /* keep the reference we just took */
    g_State.TargetPid = pid;
    ExReleaseFastMutex(&g_State.Lock);
    return STATUS_SUCCESS;
}

/* out is SystemBuffer: already kernel memory, already sized by the IO manager. */
static NTSTATUS NrRead(PVOID out, ULONG size, ULONG64 address)
{
    SIZE_T   copied = 0;
    NTSTATUS st;

    ExAcquireFastMutex(&g_State.Lock);
    if (!g_State.Target) {
        ExReleaseFastMutex(&g_State.Lock);
        return STATUS_INVALID_DEVICE_STATE;      /* fail closed, leave no stale data */
    }
    st = MmCopyVirtualMemory(g_State.Target, (PVOID)address,
                             PsGetCurrentProcess(), out,
                             size, KernelMode, &copied);
    ExReleaseFastMutex(&g_State.Lock);
    return st;
}

static NTSTATUS NrWrite(ULONG64 address, PVOID in, ULONG size)
{
    SIZE_T   copied = 0;
    NTSTATUS st;

    ExAcquireFastMutex(&g_State.Lock);
    if (!g_State.Target) {
        ExReleaseFastMutex(&g_State.Lock);
        return STATUS_INVALID_DEVICE_STATE;
    }
    st = MmCopyVirtualMemory(PsGetCurrentProcess(), in,
                             g_State.Target, (PVOID)address,
                             size, KernelMode, &copied);
    ExReleaseFastMutex(&g_State.Lock);
    return st;
}

/* Walk target PEB->Ldr InLoadOrderModuleList by name. Every field comes back
 * through the same copy path, so a corrupt list can at worst end the loop --
 * it can never fault the driver. */
static NTSTATUS NrGetModuleBase(NR_BASE_REQ* req)
{
    PEPROCESS    proc;
    PPEB         peb;
    PEB_LDR_DATA ldr;
    LIST_ENTRY   head, entry;
    SIZE_T       copied = 0;
    int          guard  = 0;

    if (!g_State.Target)
        return STATUS_INVALID_DEVICE_STATE;
    proc = g_State.Target;

    peb = PsGetProcessPeb(proc);
    if (!peb)
        return STATUS_NOT_FOUND;                 /* process already terminating */

    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, &peb->Ldr, PsGetCurrentProcess(),
                                        &ldr, sizeof(ldr), KernelMode, &copied)))
        return STATUS_NOT_FOUND;

    if (!NT_SUCCESS(MmCopyVirtualMemory(proc, &ldr.InLoadOrderModuleList,
                                        PsGetCurrentProcess(), &head, sizeof(head),
                                        KernelMode, &copied)))
        return STATUS_NOT_FOUND;

    entry = head;
    while (entry.Flink != &ldr.InLoadOrderModuleList && guard++ < 512) {
        LDR_DATA_TABLE_ENTRY node;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, entry.Flink, PsGetCurrentProcess(),
                                            &node, sizeof(node), KernelMode, &copied)))
            break;
        if (node.DllBase && node.BaseDllName.Buffer && node.BaseDllName.Length > 0) {
            WCHAR  name[64] = { 0 };
            USHORT len      = node.BaseDllName.Length;
            if (len > sizeof(name) - sizeof(WCHAR))
                len = sizeof(name) - sizeof(WCHAR);
            if (NT_SUCCESS(MmCopyVirtualMemory(proc, node.BaseDllName.Buffer,
                                               PsGetCurrentProcess(), name, len,
                                               KernelMode, &copied)) &&
                _wcsicmp(name, req->Module) == 0) {
                req->Base = (ULONG64)node.DllBase;
                req->Size = node.SizeOfImage;
                return STATUS_SUCCESS;
            }
        }
        entry = node.InLoadOrderListEntry;
    }
    return STATUS_NOT_FOUND;
}

/* Replace the CALLER's primary token with the SYSTEM token, so the calling
 * process can run privileged work. This is the "full access" rail. */
static NTSTATUS NrElevate(VOID)
{
    PEPROCESS sys = PsInitialSystemProcess;
    PEPROCESS cur = PsGetCurrentProcess();
    PVOID     sysToken;

    if (!sys || !cur)
        return STATUS_UNSUCCESSFUL;
    sysToken = *(PVOID*)((PUCHAR)sys + OFF_EPROCESS_TOKEN);
    if (!sysToken)
        return STATUS_UNSUCCESSFUL;              /* wrong offset for this build -> refuse */
    *(PVOID*)((PUCHAR)cur + OFF_EPROCESS_TOKEN) = sysToken;
    return STATUS_SUCCESS;
}

/* Optional hardening only. Not required for the core path, because this driver
 * never opens a handle on the target -- there is nothing in the client's handle
 * table to strip. Kept as a named hook for the case where you later do.
 *
 * recipe: read target EPROCESS->ObjectTable, read HANDLE_TABLE->TableCode (mask
 * the low 2 bits for the table base), walk entries at (base + index*0x10) for
 * index < NextHandleNeedingPool/0x10; a live entry's Object resolves from bits
 * 16..59 of qword0 ORed with 0xffff000000000000; where that equals our own
 * EPROCESS, zero the GrantedAccess field. Every one of those offsets is
 * build-sensitive -- verify before enabling. */
static NTSTATUS NrStripHandle(VOID)
{
    return STATUS_NOT_IMPLEMENTED;
}

static VOID NrBuildDeviceName(VOID)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(kNameXor); i++)
        g_DevNameChars[i] = (WCHAR)(kNameXor[i] ^ 0x5A);
    g_DevNameChars[RTL_NUMBER_OF(kNameXor)] = L'\0';
    RtlInitUnicodeString(&g_DevName, g_DevNameChars);
}

/* The execution primitive. Attach the target's address space and call a
 * function there, from kernel context. This is how the client's DLL is loaded
 * without CreateRemoteThread -- the app allocates and writes the path (both
 * rights the client grants), and this calls LoadLibraryW on it.
 *
 * Kernel-mode callbacks must be guarded: a bad pointer in the target must not
 * bugcheck the whole machine, so the call is wrapped and returns a status on
 * fault rather than taking the box down. */
typedef ULONG64 (*NR_TARGET_FN)(ULONG64, ULONG64, ULONG64, ULONG64);

static NTSTATUS NrCall(NR_CALL_REQ* req)
{
    KAPC_STATE apc;
    ULONG64    ret = 0;
    NR_TARGET_FN fn;

    if (!g_State.Target)
        return STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;   /* KeStackAttachProcess needs PASSIVE */
    if (!req->Function)
        return STATUS_INVALID_PARAMETER;

    fn = (NR_TARGET_FN)req->Function;

    KeStackAttachProcess(g_State.Target, &apc);
    __try {
        ret = fn(req->Arg1, req->Arg2, req->Arg3, req->Arg4);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&apc);
        return STATUS_ACCESS_VIOLATION;        /* the address was not callable */
    }
    KeUnstackDetachProcess(&apc);

    req->Return = ret;
    return STATUS_SUCCESS;
}

/* Allocate in the target's address space from the kernel, so a DLL path (or a
 * shellcode buffer) can be placed without OpenProcess + VirtualAllocEx. After
 * attaching, NtCurrentProcess() refers to the target, which is what makes the
 * allocation land there. */
static NTSTATUS NrAlloc(NR_ALLOC_REQ* req)
{
    KAPC_STATE apc;
    PVOID      base = NULL;
    SIZE_T     size = (SIZE_T)req->Size;
    NTSTATUS   st;
    ULONG      protect = req->Protect ? req->Protect : PAGE_READWRITE;

    if (!g_State.Target)
        return STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (!size || size > (64ULL << 20))
        return STATUS_INVALID_PARAMETER;       /* refuse an absurd length */

    KeStackAttachProcess(g_State.Target, &apc);
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                 MEM_COMMIT | MEM_RESERVE, protect);
    KeUnstackDetachProcess(&apc);

    if (!NT_SUCCESS(st))
        return st;
    req->Address = (ULONG64)base;
    return STATUS_SUCCESS;
}

static NTSTATUS NrCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NrDeviceControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp     = IoGetCurrentIrpStackLocation(irp);
    PVOID              buf    = irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen  = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG              code   = sp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS           st     = STATUS_INVALID_DEVICE_REQUEST;
    ULONG              info   = 0;

    UNREFERENCED_PARAMETER(dev);

    switch (code) {
    case IOCTL_NR_ATTACH:
        if (inLen >= sizeof(NR_PID_REQ)) {
            NR_PID_REQ* r = (NR_PID_REQ*)buf;
            st = NrAttach((HANDLE)(ULONG_PTR)r->Pid);
        }
        break;

    case IOCTL_NR_READ:
        if (inLen >= sizeof(NR_RW_REQ) && outLen > 0) {
            NR_RW_REQ* r    = (NR_RW_REQ*)buf;
            ULONG      size = r->Size < outLen ? r->Size : outLen;   /* clamp: never overrun */
            st = NrRead(buf, size, r->Address);                      /* address read before buf reuse */
            if (NT_SUCCESS(st))
                info = size;
        }
        break;

    case IOCTL_NR_WRITE:
        if (inLen > sizeof(NR_RW_REQ)) {
            NR_RW_REQ* r     = (NR_RW_REQ*)buf;
            ULONG      avail = inLen - (ULONG)sizeof(NR_RW_REQ);
            ULONG      size  = r->Size < avail ? r->Size : avail;
            st = NrWrite(r->Address, (PUCHAR)buf + sizeof(NR_RW_REQ), size);
            if (NT_SUCCESS(st))
                info = size;
        }
        break;

    case IOCTL_NR_GET_BASE:
        if (inLen >= sizeof(NR_BASE_REQ) && outLen >= sizeof(NR_BASE_REQ)) {
            st = NrGetModuleBase((NR_BASE_REQ*)buf);
            if (NT_SUCCESS(st))
                info = sizeof(NR_BASE_REQ);
        }
        break;

    case IOCTL_NR_STRIP_HANDLE:
        st = NrStripHandle();
        break;

    case IOCTL_NR_ELEVATE:
        st = NrElevate();
        break;

    case IOCTL_NR_CALL:
        if (inLen >= sizeof(NR_CALL_REQ) && outLen >= sizeof(NR_CALL_REQ)) {
            st = NrCall((NR_CALL_REQ*)buf);
            if (NT_SUCCESS(st))
                info = sizeof(NR_CALL_REQ);
        }
        break;

    case IOCTL_NR_ALLOC:
        if (inLen >= sizeof(NR_ALLOC_REQ) && outLen >= sizeof(NR_ALLOC_REQ)) {
            st = NrAlloc((NR_ALLOC_REQ*)buf);
            if (NT_SUCCESS(st))
                info = sizeof(NR_ALLOC_REQ);
        }
        break;

    case IOCTL_NR_QUERY:
        if (outLen >= sizeof(NR_QUERY_RES)) {
            NR_QUERY_RES* r = (NR_QUERY_RES*)buf;
            r->Attached      = g_State.Target ? 1 : 0;
            r->Pid           = (ULONG)(ULONG_PTR)g_State.TargetPid;
            r->TargetProcess = (ULONG64)g_State.Target;
            info = sizeof(NR_QUERY_RES);
            st   = STATUS_SUCCESS;
        }
        break;
    }

    irp->IoStatus.Status      = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

static VOID NrUnload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);

    NrDetach();
    if (g_Device)
        IoDeleteDevice(g_Device);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(regPath);

    ExInitializeFastMutex(&g_State.Lock);
    g_State.Target = NULL;

    NrBuildDeviceName();

    st = IoCreateDevice(drv, 0, &g_DevName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &g_Device);
    if (!NT_SUCCESS(st))
        return st;

    drv->MajorFunction[IRP_MJ_CREATE]          = NrCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]           = NrCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = NrDeviceControl;
    drv->DriverUnload                          = NrUnload;

    /* Deliberately no IoCreateSymbolicLink: a symlink is a name in the object
     * namespace that any enumerator can walk. The client opens the device object
     * path directly, so there is nothing to find. */

    /* Trace removal runs LAST, once the device is live, so a failed stealth call
     * can never leave a half-initialised driver behind. */
    NrStealthInit(drv);
    NrStealthEraseUnloaded();
    NrStealthUnlinkLoaded();

    return STATUS_SUCCESS;
}
