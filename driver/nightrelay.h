/* nightrelay.h -- interface shared by the kernel driver and its usermode client.
 *
 * The driver exposes one device object and a small IOCTL set. Everything uses
 * METHOD_BUFFERED: the IO manager copies caller data into SystemBuffer and
 * copies the output back, so the driver never touches a raw user virtual
 * address and never needs ProbeForRead on a size it did not allocate.
 */
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

#define NR_DEVICE_NAME   L"\\Device\\NightRelay"
#define NR_SYMLINK_NAME  L"\\??\\NightRelay"
#define NR_USER_PATH     L"\\\\.\\NightRelay"

#define IOCTL_NR_ATTACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_READ          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_WRITE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_GET_BASE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_STRIP_HANDLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_ELEVATE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NR_QUERY         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)

typedef struct _NR_PID_REQ {
    ULONG Pid;
} NR_PID_REQ;

typedef struct _NR_RW_REQ {
    ULONG64 Address;   /* target VA */
    ULONG   Size;      /* byte count */
    ULONG   Pad;       /* keeps the struct 16-byte aligned */
} NR_RW_REQ;

typedef struct _NR_BASE_REQ {
    WCHAR   Module[64];   /* in:  e.g. L"RobloxPlayerBeta.exe" */
    ULONG64 Base;         /* out: DllBase */
    ULONG   Size;         /* out: SizeOfImage */
    ULONG   Pad;
} NR_BASE_REQ;

typedef struct _NR_QUERY_RES {
    ULONG   Attached;
    ULONG   Pid;
    ULONG64 TargetProcess;
} NR_QUERY_RES;

#pragma pack(pop)
