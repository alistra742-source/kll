/* nr_stealth.h -- trace removal for the NightRelay driver.
 *
 * Grounded in what actually gets scanned (see the two references in README):
 *   - MmUnloadedDrivers : a ring of the last unloaded drivers, by name.
 *   - PsLoadedModuleList : the loaded-module list, walked by every enumerator.
 *   - PiDDBCacheTable    : the driver-database cache, keyed by name+timestamp.
 *
 * The rule that governs all of this: a trace is only removed AFTER the code is
 * already running, and each routine checks the field it is about to touch before
 * touching it. A wrong offset must leave memory alone, never scribble over an
 * unrelated kernel structure. Every function here fails closed.
 */
#pragma once

#include <ntddk.h>

typedef struct _NR_STEALTH_INFO {
    PVOID  ImageBase;    /* base of our own image, captured at entry */
    SIZE_T ImageSize;
} NR_STEALTH_INFO;

/* Capture our own image bounds. Call first, from DriverEntry. */
VOID NrStealthInit(_In_ PDRIVER_OBJECT DriverObject);

/* Remove our entry from the unloaded-driver ring (MmUnloadedDrivers). */
VOID NrStealthEraseUnloaded(VOID);

/* Unlink our LDR_DATA_TABLE_ENTRY from PsLoadedModuleList. Safe to call when we
 * were never in the list (manual-mapped): the search simply finds nothing. */
VOID NrStealthUnlinkLoaded(VOID);

/* Best-effort PiDDBCacheTable scrub. Offsets are build-sensitive; the routine
 * resolves them by scan and no-ops if it cannot. */
VOID NrStealthEraseDdb(VOID);
