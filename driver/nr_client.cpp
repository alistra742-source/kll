/* nr_client.cpp -- usermode side of the NightRelay driver.
 *
 * Opens the device without a symbolic link: a symlink is a name any enumerator
 * can find, so the driver creates none and this opens the device object path
 * directly through NtOpenFile. DeviceIoControl still works on the resulting
 * handle.
 *
 * Build: cl /nologo /EHsc /O2 /W4 /std:c++17 nr_client.cpp /link ntdll.lib
 */
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include "nightrelay.h"

#pragma comment(lib, "ntdll.lib")

/* NTSTATUS-returning open, declared locally so we do not drag in the full WDK. */
typedef NTSTATUS(NTAPI* NtOpenFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

#define OBJ_CASE_INSENSITIVE_ 0x00000040UL
#define FILE_SYNCHRONOUS_IO_NONALERT_ 0x00000020UL

static NtOpenFile_t pNtOpenFile = nullptr;

/* The device object path is not linked into the name space, so no \\.\ alias
 * exists and no symlink string is present anywhere on disk. */
static const wchar_t* kDevicePath = L"\\Device\\NightRelay";

static HANDLE OpenDriver()
{
    if (!pNtOpenFile) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        pNtOpenFile = reinterpret_cast<NtOpenFile_t>(
            GetProcAddress(ntdll, "NtOpenFile"));
        if (!pNtOpenFile)
            return INVALID_HANDLE_VALUE;
    }

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, kDevicePath);

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE_, nullptr, nullptr);

    IO_STATUS_BLOCK iosb{};
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS st = pNtOpenFile(&handle, GENERIC_READ | GENERIC_WRITE,
                              &attr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              FILE_SYNCHRONOUS_IO_NONALERT_);
    if (!NT_SUCCESS(st))
        return INVALID_HANDLE_VALUE;
    return handle;
}

class Driver {
    HANDLE h_ = INVALID_HANDLE_VALUE;
public:
    bool Open() { h_ = OpenDriver(); return h_ != INVALID_HANDLE_VALUE; }
    bool IsOpen() const { return h_ != INVALID_HANDLE_VALUE; }

    bool Attach(DWORD pid) {
        NR_PID_REQ req{ pid };
        DWORD ret = 0;
        return DeviceIoControl(h_, IOCTL_NR_ATTACH, &req, sizeof(req),
                               nullptr, 0, &ret, nullptr) != FALSE;
    }

    bool Read(uint64_t address, void* out, uint32_t size) {
        NR_RW_REQ req{ address, size, 0 };
        DWORD ret = 0;
        return DeviceIoControl(h_, IOCTL_NR_READ, &req, sizeof(req),
                               out, size, &ret, nullptr) != FALSE && ret == size;
    }

    bool Write(uint64_t address, const void* in, uint32_t size) {
        std::vector<uint8_t> buf(sizeof(NR_RW_REQ) + size);
        auto* req = reinterpret_cast<NR_RW_REQ*>(buf.data());
        req->Address = address;
        req->Size    = size;
        req->Pad     = 0;
        memcpy(buf.data() + sizeof(NR_RW_REQ), in, size);
        DWORD ret = 0;
        return DeviceIoControl(h_, IOCTL_NR_WRITE, buf.data(),
                               static_cast<DWORD>(buf.size()),
                               nullptr, 0, &ret, nullptr) != FALSE;
    }

    bool GetBase(const std::wstring& module, uint64_t& base, uint32_t& size) {
        NR_BASE_REQ req{};
        wcsncpy_s(req.Module, module.c_str(), _TRUNCATE);
        DWORD ret = 0;
        if (!DeviceIoControl(h_, IOCTL_NR_GET_BASE, &req, sizeof(req),
                             &req, sizeof(req), &ret, nullptr))
            return false;
        base = req.Base;
        size = req.Size;
        return base != 0;
    }

    bool Elevate() {
        DWORD ret = 0;
        return DeviceIoControl(h_, IOCTL_NR_ELEVATE, nullptr, 0,
                               nullptr, 0, &ret, nullptr) != FALSE;
    }

    void Close() {
        if (h_ != INVALID_HANDLE_VALUE) { CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; }
    }
};

static DWORD FindPid(const std::wstring& name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int wmain()
{
    Driver drv;
    if (!drv.Open()) {
        wprintf(L"[!] driver not reachable (load it in the guest first)\n");
        return 1;
    }
    wprintf(L"[+] driver open\n");

    for (;;) {
        wprintf(L"\n[1] attach   [2] read   [3] write   [4] base   [5] elevate   [6] pid   [0] exit\n> ");
        int choice = 0;
        if (wscanf_s(L"%d", &choice) != 1)
            break;

        if (choice == 0)
            break;
        if (choice == 1) {
            DWORD pid = FindPid(L"RobloxPlayerBeta.exe");
            if (!pid) { wprintf(L"[!] RobloxPlayerBeta.exe not running\n"); continue; }
            wprintf(drv.Attach(pid) ? L"[+] attached to %lu\n" : L"[!] attach failed\n", pid);
        } else if (choice == 2) {
            unsigned long long addr = 0; unsigned size = 0;
            wprintf(L"address (hex): "); wscanf_s(L"%llx", &addr);
            wprintf(L"size: ");          wscanf_s(L"%u", &size);
            std::vector<uint8_t> out(size);
            if (drv.Read(addr, out.data(), size))
                wprintf(L"[+] read %u bytes\n", size);
            else
                wprintf(L"[!] read refused\n");
        } else if (choice == 3) {
            unsigned long long addr = 0; unsigned val = 0;
            wprintf(L"address (hex): "); wscanf_s(L"%llx", &addr);
            wprintf(L"value (hex): ");   wscanf_s(L"%x", &val);
            wprintf(drv.Write(addr, &val, sizeof(val)) ? L"[+] wrote\n" : L"[!] write refused\n");
        } else if (choice == 4) {
            uint64_t base = 0; uint32_t size = 0;
            if (drv.GetBase(L"RobloxPlayerBeta.exe", base, size))
                wprintf(L"[+] base 0x%llX size 0x%X\n", base, size);
            else
                wprintf(L"[!] module not found\n");
        } else if (choice == 5) {
            wprintf(drv.Elevate() ? L"[+] token raised to SYSTEM\n" : L"[!] elevate refused\n");
        } else if (choice == 6) {
            wprintf(L"[+] Roblox pid: %lu\n", FindPid(L"RobloxPlayerBeta.exe"));
        }
    }

    drv.Close();
    return 0;
}
