// ============================================================================
// packet/injection.c — injection lifecycle (gate + drain + handle/pool
// owner)
//
// Protocol (contract in injection.h; correctness argument in
// runtime/rundown.h and runtime/runtime.h):
//   * an injection path must ShInjectionBegin() (rundown acquire)
//     before using the handles;
//   * quiesce: GateStop (stop bit; Begin fails afterwards) -> drain
//     in-flight -> ShInjectionDestroyTracked destroys the handles
//     (bounded BUSY retries; unknown error/exhausted => Leaked =>
//     caller parks);
//   * self-injection guard: SK_INJECT_TAG is written into the low 32
//     bits of the injection context at submit time; SkInjectIsSelf in
//     classify permits such packets directly, preventing
//     re-classification loops.
//
// Reference-pairing contract for wiring a reinject callout:
//   * ShInjectionBegin() must succeed before queueing/submitting;
//     Begin failure = gate closed (GateStop in effect): abandon the
//     injection and free the packet yourself — no completion will
//     arrive, do not call ShInjectionEnd();
//   * a submit-failure path returns the reference immediately
//     (ShInjectionEnd) and frees the built NBL;
//   * completion returns the reference exactly once (ShInjectionEnd)
//     and frees the NBL — no more, no less: one extra => drain count
//     underflow / handle UAF; one short => drain never reaches zero
//     (park).
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "injection.h"

#define SK_INJECT_BUSY_RETRIES 8  // bounded BUSY retry limit for handle destroy
#define SK_INJECT_RETRY_DELAY_MS 10
#define SK_INJECT_DRAIN_RETRIES 100 // drain in-flight limit (polling)
#define SK_NBL_POOL_TAG 0x6C6E6B53u /* 'Sknl' */
#define SK_NB_POOL_TAG  0x626E6B53u /* 'Sknb' */

// [0] = AF_INET, [1] = AF_INET6; handles + destroy tracking + packet pools (image-level storage)
HANDLE g_InjectionHandle[2];
static SHINKEN_WFP_OBJECT g_InjectionTrack[2];
PVOID g_SkNblPool;
PVOID g_SkNbPool;
static LONG g_SkInjectInited;   // state bit: 1 <=> both handles AND both pools exist (strict pairing)
static LONG g_SkInjectQuiesced; // set by a fully successful quiesce: the injection
                                // rundown gate is then permanently stopped, so
                                // SkInjectInit refuses re-init (provable re-init semantics)

// create injection handles + NBL/NB pools; all return values checked; partial failure rolls back what was built.
//
// State-bit discipline (P2 defect fix — must be provable):
//   g_SkInjectInited==1  <=>  handles[0..1] and pools exist and are usable;
//   g_SkInjectInited==0  <=>  none of them is relied upon (nothing created, or
//                             fully quiesced/destroyed, or a failed init that
//                             rolled everything back).
// The claim is a single CAS; EVERY failure path below resets the bit to 0
// after rolling back the resources claimed so far, so the invariant "bit ==
// resources" holds after any return. A second Init while initialized is a
// no-op success (idempotent). After a successful quiesce the gate rundown's
// stop bit is irreversible (rundown.h invariant 7): re-init would create
// handles behind a permanently closed ShInjectionBegin gate, so it is
// refused with STATUS_INVALID_DEVICE_STATE and the bit stays 0.
NTSTATUS SkInjectInit(void) {
    NET_BUFFER_LIST_POOL_PARAMETERS nblParams;
    NET_BUFFER_POOL_PARAMETERS nbParams;
    NTSTATUS st;

    if (SkAtOr32(&g_SkInjectQuiesced, 0))
        return STATUS_INVALID_DEVICE_STATE; // gate permanently stopped; re-init refused, bit stays 0
    if (SkAtCas32(&g_SkInjectInited, 1, 0) != 0)
        return STATUS_SUCCESS; // already initialized: bit==1 => handles+pools exist (invariant below)

    ShWfpObjectInit(&g_InjectionTrack[0], "injectHandleV4", 0, 0, NULL);
    ShWfpObjectInit(&g_InjectionTrack[1], "injectHandleV6", 0, 0, NULL);

    st = FwpsInjectionHandleCreate0(AF_INET, 0, &g_InjectionHandle[0]);
    if (!NT_SUCCESS(st)) {
        g_InjectionHandle[0] = NULL;
        g_SkInjectInited = 0;
        return st;
    }
    st = FwpsInjectionHandleCreate0(AF_INET6, 0, &g_InjectionHandle[1]);
    if (!NT_SUCCESS(st)) {
        g_InjectionHandle[1] = NULL;
        ShOps.InjectionHandleDestroy(g_InjectionHandle[0]); // roll back the v4 handle already created
        g_InjectionHandle[0] = NULL;
        g_SkInjectInited = 0;
        return st;
    }

    // NDIS_OBJECT_HEADER must carry Type/Revision: with only Size set,
    // NdisAllocateNetBufferListPool rejects the parameters and returns
    // NULL.
    RtlZeroMemory(&nblParams, sizeof(nblParams));
    nblParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nblParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblParams.Header.Size = (USHORT)sizeof(NET_BUFFER_LIST_POOL_PARAMETERS);
    nblParams.PoolTag = SK_NBL_POOL_TAG;
    g_SkNblPool = NdisAllocateNetBufferListPool(NULL, &nblParams);
    if (g_SkNblPool == NULL) {
        ShOps.InjectionHandleDestroy(g_InjectionHandle[1]);
        ShOps.InjectionHandleDestroy(g_InjectionHandle[0]);
        g_InjectionHandle[0] = g_InjectionHandle[1] = NULL;
        g_SkInjectInited = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&nbParams, sizeof(nbParams));
    nbParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbParams.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbParams.Header.Size = (USHORT)sizeof(NET_BUFFER_POOL_PARAMETERS);
    nbParams.PoolTag = SK_NB_POOL_TAG;
    g_SkNbPool = NdisAllocateNetBufferPool(NULL, &nbParams);
    if (g_SkNbPool == NULL) {
        NdisFreeNetBufferListPool(g_SkNblPool);
        g_SkNblPool = NULL;
        ShOps.InjectionHandleDestroy(g_InjectionHandle[1]);
        ShOps.InjectionHandleDestroy(g_InjectionHandle[0]);
        g_InjectionHandle[0] = g_InjectionHandle[1] = NULL;
        g_SkInjectInited = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

// quiesce: close gate -> drain in-flight -> destroy both injection handles.
// Any failure -> record ShinkenBlockInjectionDrain and return FALSE (caller
// blocks unload; pool stays: completions may still touch it).
// Drain verdict must be exact STATUS_SUCCESS: SHINKEN_STATUS_TIMEOUT (0x102)
// is positive and NT_SUCCESS would misread it as drained.
BOOLEAN SkInjectQuiesce(void) {
    NTSTATUS st;
    ULONG i;

    if (!SkAtOr32(&g_SkInjectInited, 0))
        return TRUE; // idempotent: uninitialized = nothing to quiesce (atomic state-bit read)

    ShInjectionGateStop();
    st = ShInjectionDrain(SK_INJECT_DRAIN_RETRIES, SK_INJECT_RETRY_DELAY_MS);
    if (st != STATUS_SUCCESS) {
        // in-flight injections never complete: handles/pools/completion code all stay resident
        ShRuntimeRecordBlock(ShinkenBlockInjectionDrain);
        return FALSE;
    }
    for (i = 0; i < 2; i++) {
        st = ShInjectionDestroyTracked(&g_InjectionTrack[i], g_InjectionHandle[i],
                                       SK_INJECT_BUSY_RETRIES, SK_INJECT_RETRY_DELAY_MS);
        if (g_InjectionTrack[i].state == ShWfpDeleted) {
            g_InjectionHandle[i] = NULL;
        } else if (st != STATUS_SUCCESS) {
            // destroy not confirmed (BUSY exhausted or unknown error): track
            // entry is Leaked, completion may still execute -> block unload
            ShRuntimeRecordBlock(ShinkenBlockInjectionDrain);
            return FALSE;
        }
    }
    // Full success (P2 defect fix): the injection gate is permanently closed
    // and both handles are destroyed, so "initialized" is no longer true —
    // reset the state bit to keep bit<->resources strictly paired, and latch
    // quiesced so a later SkInjectInit is refused instead of silently
    // creating handles behind the dead gate.
    SkAtXchg32(&g_SkInjectInited, 0);
    SkAtXchg32(&g_SkInjectQuiesced, 1);
    return TRUE;
}

// destroy phase (called by lifecycle only after quiesce fully succeeds): free the pools.
VOID SkInjectDestroy(void) {
    if (g_SkNbPool) {
        NdisFreeNetBufferPool(g_SkNbPool);
        g_SkNbPool = NULL;
    }
    if (g_SkNblPool) {
        NdisFreeNetBufferListPool(g_SkNblPool);
        g_SkNblPool = NULL;
    }
}

// self-injection check: this driver's packets carry SK_INJECT_TAG in the low 32 bits of the injection context.
BOOLEAN SkInjectIsSelf(UINT64 injectionContext) {
    return (BOOLEAN)((UINT32)(injectionContext & 0xFFFFFFFFu) == SK_INJECT_TAG);
}
