// ============================================================================
// wdk_shim.h — Minimal WDK/WFP type & API shim, only for clang syntax
// checking / optimization of restored code. NOT a WDK replacement: structs
// contain only the accessed fields; APIs are declared with empty parameter
// lists (call arguments unchecked).
// ============================================================================
#pragma once
#include <stdint.h>
#include <string.h>

#ifndef NTAPI
#define NTAPI __stdcall
#endif
#ifndef __stdcall
#define __stdcall __attribute__((stdcall))
#endif
#ifndef __fastcall
#define __fastcall __attribute__((fastcall))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int8_t   CHAR;      typedef uint8_t  UCHAR, BYTE, BOOLEAN;
typedef int16_t  SHORT;     typedef uint16_t USHORT, WORD, WCHAR;
typedef int32_t  LONG, INT; typedef uint32_t ULONG, UINT, DWORD;
typedef int64_t  LONGLONG;  typedef uint64_t ULONGLONG, QWORD, ULONG64;
typedef int32_t  BOOL, INT_PTR; typedef uint32_t UINT_PTR;
typedef LONGLONG LONG64;
typedef long LONG_PTR; typedef unsigned long ULONG_PTR, SIZE_T;
typedef void VOID; typedef void *PVOID, *HANDLE, *LPVOID;
typedef char *PCHAR; typedef WCHAR *PWSTR; typedef const WCHAR *PCWSTR;
typedef uint8_t *PUCHAR; typedef uint16_t *PUSHORT; typedef uint32_t *PULONG;
typedef uint8_t UINT8; typedef uint16_t UINT16; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef int INT32; typedef uint32_t UINT32_T;
typedef int64_t INT64; typedef int16_t INT16; typedef int8_t INT8;
typedef struct _DRIVER_OBJECT { int x[16]; void *DriverUnload; } DRIVER_OBJECT;
typedef VOID (*PDRIVER_UNLOAD)(DRIVER_OBJECT *);
typedef struct _DRIVER_OBJECT _DRIVER_OBJECT;
typedef UCHAR _BYTE; typedef USHORT _WORD; typedef ULONG _DWORD; typedef ULONG64 _QWORD;

typedef struct _FWP_BYTE_ARRAY16 { uint8_t byteArray16[16]; } FWP_BYTE_ARRAY16;
#define FWP_BYTE_ARRAY16_TYPE 11
typedef LONG NTSTATUS;
typedef CHAR KIRQL; typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;
typedef ULONG EX_SPIN_LOCK;
typedef EX_SPIN_LOCK *PEX_SPIN_LOCK;
typedef PVOID PEPROCESS, PKTHREAD, PDEVICE_OBJECT, PDRIVER_OBJECT, PFILE_OBJECT;
typedef struct _MDL { struct _MDL *Next; int16_t Size; int16_t MdlFlags; void *Process; void *MappedSystemVa; void *StartVa; ULONG ByteCount; ULONG ByteOffset; } MDL, *PMDL;
typedef struct _GUID { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;
typedef const GUID *LPCGUID, *PCGUID;
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef union _LARGE_INTEGER { struct { ULONG LowPart; LONG HighPart; }; int64_t QuadPart; } LARGE_INTEGER;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct _KLOCK_QUEUE_HANDLE { void *LockQueue; KIRQL OldIrql; } KLOCK_QUEUE_HANDLE, *PKLOCK_QUEUE_HANDLE;
typedef struct _RTL_OSVERSIONINFOW { ULONG dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId; WCHAR szCSDVersion[128]; } RTL_OSVERSIONINFOW, OSVERSIONINFOW;
typedef struct _KEVENT { long x[6]; } KEVENT, *PKEVENT;
typedef struct _IO_WORKITEM { long x[4]; } IO_WORKITEM, *PIO_WORKITEM;
typedef struct _KDPC { long x[8]; } KDPC;
typedef int KPROCESSOR_MODE;
typedef struct _FWP_BYTE_BLOB { uint32_t size; uint8_t *data; } FWP_BYTE_BLOB;
typedef struct _FWP_DISPLAY_DATA { PWSTR name, description; } FWPM_DISPLAY_DATA0;
typedef struct _FWP_VALUE0 { UINT32 type; union { UINT8 uint8; UINT16 uint16; UINT32 uint32; UINT64 *uint64; void *blob; FWP_BYTE_ARRAY16 *byteArray16; }; } FWP_VALUE0;
enum { FWP_EMPTY = 0, FWP_UINT8 = 4 - 3, FWP_UINT16, FWP_UINT32, FWP_UINT64 };  // FWP_UINT8=1, FWP_UINT64=4
typedef struct _FWPM_ACTION0 { UINT32 type; union { GUID filterType; GUID calloutKey; }; } FWPM_ACTION0;
typedef struct _FWPM_FILTER_CONDITION0 { GUID fieldKey; UINT32 matchType; void *conditionValue; } FWPM_FILTER_CONDITION0;
typedef struct _FWPM_FILTER0 {
    GUID filterKey; FWPM_DISPLAY_DATA0 displayData; UINT32 flags; GUID *providerKey;
    FWP_BYTE_BLOB providerData; GUID layerKey, subLayerKey; FWP_VALUE0 weight;
    UINT32 numFilterConditions; FWPM_FILTER_CONDITION0 *filterCondition; FWPM_ACTION0 action;
    union { UINT64 rawContext; GUID providerContextKey; }; void *reserved; UINT64 filterId;
    FWP_VALUE0 effectiveWeight;
} FWPM_FILTER0;
typedef struct _FWPS_INCOMING_METADATA_VALUES0 { uint64_t currentFrameValues; uint64_t flags; uint64_t reserved; uint64_t discardReason; uint64_t flowHandle; uint32_t ipHeaderSize; uint32_t transportHeaderSize; uint64_t processId; uint64_t processPath_x; uint64_t transportEndpointHandle; uint64_t parentEndpointHandle; uint64_t x[8]; } FWPS_INCOMING_METADATA_VALUES0;
typedef struct _FWPM_PROVIDER0 { GUID providerKey; FWPM_DISPLAY_DATA0 displayData; UINT32 flags; FWP_BYTE_BLOB providerData; PWSTR serviceName; } FWPM_PROVIDER0;
typedef struct _FWPM_SUBLAYER0 { GUID subLayerKey; FWPM_DISPLAY_DATA0 displayData; UINT32 flags; GUID *providerKey; FWP_BYTE_BLOB providerData; UINT16 weight; } FWPM_SUBLAYER0;
typedef struct _FWPS_INCOMING_VALUE0 { FWP_VALUE0 value; } FWPS_INCOMING_VALUE0;
typedef struct _FWPS_INCOMING_VALUES0 { uint16_t layerId; uint16_t pad; uint32_t valueCount; FWPS_INCOMING_VALUE0 *incomingValue; } FWPS_INCOMING_VALUES0;

typedef struct _FWPS_FILTER0 { long x[24]; } FWPS_FILTER0;
typedef struct _FWPS_FILTER1 { long x[24]; } FWPS_FILTER1;
typedef struct _FWPS_CLASSIFY_OUT0 { UINT32 actionType; UINT64 rights; UINT32 flags; UINT32 reserved; } FWPS_CLASSIFY_OUT0;
typedef struct _FWPS_STREAM_DATA0 { UINT64 flags; UINT64 dataLength; long x[6]; } FWPS_STREAM_DATA0;
typedef UINT32 FWPS_CALLOUT_NOTIFY_TYPE;
typedef VOID (NTAPI *FWPS_CALLOUT_CLASSIFY_FN0)(const FWPS_INCOMING_VALUES0 *, const FWPS_INCOMING_METADATA_VALUES0 *, VOID *, const void *, const FWPS_FILTER0 *, UINT64, FWPS_CLASSIFY_OUT0 *);
typedef VOID (NTAPI *FWPS_CALLOUT_CLASSIFY_FN1)(const FWPS_INCOMING_VALUES0 *, const FWPS_INCOMING_METADATA_VALUES0 *, VOID *, const void *, const FWPS_FILTER1 *, UINT64, FWPS_CLASSIFY_OUT0 *);
typedef NTSTATUS (NTAPI *FWPS_CALLOUT_NOTIFY_FN0)(FWPS_CALLOUT_NOTIFY_TYPE, const GUID *, FWPS_FILTER0 *);
typedef NTSTATUS (NTAPI *FWPS_CALLOUT_NOTIFY_FN1)(FWPS_CALLOUT_NOTIFY_TYPE, const GUID *, FWPS_FILTER1 *);
typedef VOID (NTAPI *FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(UINT16, UINT32, UINT64);
typedef struct _FWPS_CALLOUT0 { GUID calloutKey; UINT32 flags; FWPS_CALLOUT_CLASSIFY_FN0 classifyFn; FWPS_CALLOUT_NOTIFY_FN0 notifyFn; FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn; } FWPS_CALLOUT0;
typedef struct _FWPS_CALLOUT1 { GUID calloutKey; UINT32 flags; FWPS_CALLOUT_CLASSIFY_FN1 classifyFn; FWPS_CALLOUT_NOTIFY_FN1 notifyFn; FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn; } FWPS_CALLOUT1;
typedef struct _FWPM_CALLOUT0 { GUID calloutKey; FWPM_DISPLAY_DATA0 displayData; UINT32 flags; GUID *providerKey; FWP_BYTE_BLOB providerData; GUID applicableLayer; UINT32 calloutId; } FWPM_CALLOUT0;
enum { FWPS_PACKET_INJECTED_BY_SELF = 0, FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF = 1, FWPS_PACKET_INJECTED_BY_OTHER = 2, FWPS_PACKET_INJECTION_STATE_MAX = 3 };
typedef int FWPM_SERVICE_STATE;
typedef HANDLE WDFOBJECT;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif
#define FILE_DEVICE_UNKNOWN 0x22
#define FILE_DEVICE_SECURE_OPEN 0x100
// Forward: API declaration macro (takes effect in the API section below)
#define DECL0(ret, name) ret name();
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define FILE_DEVICE_NETWORK 0x12
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_INVALID_PARAMETER_1 ((NTSTATUS)0xC00000EFL)
#define IPPROTO_ICMP 1
typedef ULONG LOGICAL;
typedef struct _STRING { USHORT Length, MaximumLength; PCHAR Buffer; } STRING, *PSTRING;
typedef int FWPS_PACKET_INJECTION_STATE;
enum { FWPM_SERVICE_STOPPED = 0, FWPM_SERVICE_START_PENDING = 1, FWPM_SERVICE_STOP_PENDING = 2, FWPM_SERVICE_RUNNING = 3 };
#define KernelMode 0
#define UserMode 1
#define Executive 0
#define MmCached 1
#define STATUS_PIPE_EMPTY ((NTSTATUS)0xC00000D9L)
#define STATUS_HOPLIMIT_EXCEEDED ((NTSTATUS)0xC000A012L)
#define MmNonCached 0
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#define STATUS_WAIT_0 ((NTSTATUS)0x00000000L)
#define WaitAny 0
#define WaitAll 1
typedef struct _CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID;
#define OBJ_KERNEL_HANDLE 0x200
#define THREAD_ALL_ACCESS 0x1FFFFF
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#define NotificationEvent 0
#define SynchronizationEvent 1
DECL0(VOID, ExAcquireSpinLockExclusiveAtDpcLevel); DECL0(VOID, ExReleaseSpinLockExclusiveFromDpcLevel);
DECL0(KIRQL, KeGetCurrentIrql);
typedef union _NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO { struct { ULONG TxIpHeaderChecksum:1, TxTcpChecksum:1, TxUdpChecksum:1, TxIpChecksum:1, RxIpChecksumSucceeded:1, RxTcpChecksumSucceeded:1, RxUdpChecksumSucceeded:1; }; UINT64 Value; } NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO;
#define TcpIpChecksumNetBufferListInfo 0
#define NET_BUFFER_LIST_INFO(nbl, id) ((nbl)->NetBufferListInfo[(id)])
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define NET_BUFFER_LIST_FIRST_NB(nbl) ((nbl)->FirstNetBuffer)
#define UNSPECIFIED_COMPARTMENT_ID 0
#define AF_INET 2
#define AF_INET6 23
typedef int POOL_TYPE;
#define RtlZeroMemory(d, l) memset((d), 0, (l))
#define RtlFillMemory(d, l, f) memset((d), (f), (l))
extern POOL_TYPE PoolType;
extern UNICODE_STRING SkDvSddlSysAdmAll;
#define SDDL_DEVOBJ_SYS_ALL_ADM_ALL SkDvSddlSysAdmAll
#define RtlCopyMemory(d, s, l) memcpy((d), (s), (l))
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011L)
#endif
#define FWP_ACTION_BLOCK (0x00000001 | 0x00001000)
#define FWP_ACTION_CALLOUT_TERMINATING (0x00000003 | 0x00004000 | 0x00001000)
#define FWP_ACTION_CALLOUT_INSPECTION (0x00000004 | 0x00004000 | 0x00002000)
#define FWP_ACTION_PERMIT (0x00000002 | 0x00001000)
#define FWPS_RIGHT_ACTION_WRITE 0x00000001
// ALE-layer inFixedValues field indices (FWPS_FIELD_ALE_AUTH_CONNECT_V4_* in
// fwpsk.h; all four ALE layer groups are isomorphic):
// protocol/address/port/direction
#define SK_FIELD_PROTOCOL     0  // FWPS_FIELD_*_IP_PROTOCOL
#define SK_FIELD_LOCAL_ADDR   1  // IP_LOCAL_ADDRESS
#define SK_FIELD_REMOTE_ADDR  2  // IP_REMOTE_ADDRESS
#define SK_FIELD_LOCAL_PORT   3  // IP_LOCAL_PORT
#define SK_FIELD_REMOTE_PORT  4  // IP_REMOTE_PORT
#define SK_FIELD_DIRECTION    5  // DIRECTION(0=out,1=in)
// metadata flags (bits of FWPS_INCOMING_METADATA_VALUES0.flags)
#define SK_META_PROCESS_ID    0x00000010 // FWPS_METADATA_FIELD_PROCESS_ID
#define SK_META_PROCESS_PATH  0x00000040 // FWPS_METADATA_FIELD_PROCESS_PATH
#define SK_META_ALE_USER_ID   0x00400000 // FWPS_METADATA_FIELD_ALE_USER_ID(approximate)
DECL0(VOID, KeQuerySystemTime); DECL0(VOID, KeQuerySystemTimePrecise);
#define METHOD_BUFFERED 0
#define METHOD_IN_DIRECT 1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0
#define CTL_CODE(t, f, m, a) (((t) << 16) | ((a) << 14) | ((f) << 2) | (m))
#define DRIVER_INITIALIZE NTSTATUS __stdcall
typedef NTSTATUS(__stdcall DRIVER_INIT_FUNCTION)(void *, void *);
#define FWP_ACTION_CALLOUT_UNKNOWN (0x00000005 | 0x00004000)
#define NonPagedPool 0
#define NonPagedPoolNx 512
#define DelayedWorkQueue 1
#define CriticalWorkQueue 2
#define RPC_C_AUTHN_WINNT 10
#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFFu
typedef struct _NET_BUFFER { ULONG DataLength; long x[7]; } NET_BUFFER, *PNET_BUFFER;
typedef struct _NDIS_OBJECT_HEADER { UCHAR Type; UCHAR Revision; USHORT Size; } NDIS_OBJECT_HEADER;
#define NDIS_OBJECT_TYPE_DEFAULT 0x80
#define NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 1
#define NET_BUFFER_POOL_PARAMETERS_REVISION_1 1
// NDIS
typedef struct _NET_BUFFER_LIST { PNET_BUFFER FirstNetBuffer; NTSTATUS Status; union { PVOID Region; PVOID Pointer; } Link; void *NetBufferListInfo[8]; } NET_BUFFER_LIST, *PNET_BUFFER_LIST;
typedef struct _NET_BUFFER_LIST_POOL_PARAMETERS { NDIS_OBJECT_HEADER Header; ULONG PoolTag; ULONG DataSize; ULONG ProtocolId; long x[4]; } NET_BUFFER_LIST_POOL_PARAMETERS;
typedef struct _NET_BUFFER_POOL_PARAMETERS { NDIS_OBJECT_HEADER Header; ULONG PoolTag; ULONG DataSize; ULONG ProtocolId; long x[4]; } NET_BUFFER_POOL_PARAMETERS;


// ---- Hex-Rays pseudo-macros (byte access into 128-bit locals in restored
//      code; assignable forms) ----
#define LODWORD(x)  (*((UINT32*)&(x)+0))
#define DWORD1(x)   (*((UINT32*)&(x)+1))
#define HIDWORD(x)  (*((UINT32*)&(x)+3))   // [per this codebase's 16-byte operand usage: bytes 12-15]
#define LOBYTE(x)   (*((UCHAR*)&(x)+0))
#define BYTE1(x)    (*((UCHAR*)&(x)+1))
#define HIBYTE(x)   (*((UCHAR*)&(x)+15))
#define WORD2(x)    (*((UINT16*)&(x)+2))
#define WORD4(x)    (*((UINT16*)&(x)+4))
#define WORD5(x)    (*((UINT16*)&(x)+5))
#define __ROR2__(v,n) ((UINT16)(((UINT16)(v) >> (n)) | ((UINT16)(v) << (16-(n)))))
#define __CFSHR__(x,n) ((x) >> (n))
typedef struct { UINT64 lo, hi; } OWORD;
typedef struct _OBJECT_NAME_INFORMATION { UNICODE_STRING Name; } OBJECT_NAME_INFORMATION;
#define PagedPool 1
typedef OWORD _OWORD;
// WDF (treated as opaque handles)
typedef HANDLE WDFDRIVER, WDFDEVICE, WDFQUEUE, WDFWORKITEM, WDFREQUEST, WDFFILEOBJECT, WDFCMRESLIST;
typedef HANDLE WDFMEMORY;
typedef PVOID WDFCONTEXT;
typedef struct _WDF_REQUEST_PARAMETERS { ULONG Size; ULONG MinorFunction; ULONG MajorFunction; union { struct { ULONG IoControlCode; ULONG_PTR InputBufferLength; ULONG_PTR OutputBufferLength; } DeviceIoControl; UCHAR Raw[24]; } Parameters; UCHAR Rest[64]; } WDF_REQUEST_PARAMETERS;
#define IRP_MJ_DEVICE_CONTROL 14
typedef PVOID PIRP;
typedef struct _SID { UCHAR Revision; UCHAR SubAuthorityCount; UCHAR IdentifierAuthority[6]; ULONG SubAuthority[1]; } SID;
typedef struct _FWPM_SESSION0 { GUID sessionKey; FWPM_DISPLAY_DATA0 displayData; UINT32 flags; UINT32 txnWaitTimeoutInMSec; DWORD processId; SID *sid; PWSTR username; BOOL kernelMode; } FWPM_SESSION0;
typedef struct _WDFDEVICE_INIT WDFDEVICE_INIT, *PWDFDEVICE_INIT;
typedef struct _WDF_OBJECT_ATTRIBUTES { ULONG Size; PVOID ContextTypeInfo; PVOID EvtCleanupCallback; PVOID EvtDestroyCallback; int ExecutionLevel; int SynchronizationScope; PVOID ParentObject; } WDF_OBJECT_ATTRIBUTES;
typedef struct _WDF_DRIVER_CONFIG { ULONG Size; PVOID EvtDriverDeviceAdd; PVOID EvtDriverUnload; ULONG DriverInitFlags; ULONG DriverPoolTag; ULONG PowerManaged; } WDF_DRIVER_CONFIG;
typedef struct _WDF_FILEOBJECT_CONFIG { ULONG Size; PVOID EvtDeviceFileCreate; PVOID EvtFileClose; PVOID EvtFileCleanup; PVOID EvtFileCleanup2; int AutoForwardCleanupClose; int FsContextUse; int FileObjectClass; } WDF_FILEOBJECT_CONFIG;
typedef struct _WDF_IO_QUEUE_CONFIG { ULONG Size; int DispatchType; int PowerManaged; BOOLEAN AllowZeroLengthRequests; BOOLEAN DefaultQueue; PVOID EvtIoDefault; PVOID EvtIoRead; PVOID EvtIoWrite; PVOID EvtIoDeviceControl; PVOID EvtIoInternalDeviceControl; union { struct { ULONG NumberOfPresentedRequests; } Parallel; } Settings; } WDF_IO_QUEUE_CONFIG;
typedef struct _WDF_WORKITEM_CONFIG { ULONG Size; PVOID EvtWorkItemFunc; BOOLEAN AutomaticSerialization; } WDF_WORKITEM_CONFIG;
typedef struct _WDF_REQUEST_RETRIEVAL_PARAMS { ULONG Size; PVOID Parameters; } WDF_REQUEST_RETRIEVAL_PARAMS;

// ---- WDF enums (values match the real WDK; production code uses symbolic
//      names only, never bare numbers) ----
// WDF_TRI_STATE: note WdfUseDefault=0/WdfFalse=1/WdfTrue=2, counter-intuitive.
typedef enum _WDF_TRI_STATE { WdfUseDefault = 0, WdfFalse = 1, WdfTrue = 2 } WDF_TRI_STATE;
typedef enum _WDF_DEVICE_IO_TYPE { WdfDeviceIoUndefined = 0, WdfDeviceIoNeither = 1,
    WdfDeviceIoBuffered = 2, WdfDeviceIoDirect = 3, WdfDeviceIoBufferedOrDirect = 4,
    WdfDeviceIoMaximum = 5 } WDF_DEVICE_IO_TYPE;
typedef enum _WDF_EXECUTION_LEVEL { WdfExecutionLevelInvalid = 0,
    WdfExecutionLevelInheritFromParent = 1, WdfExecutionLevelPassive = 2,
    WdfExecutionLevelDispatch = 3 } WDF_EXECUTION_LEVEL;
typedef enum _WDF_SYNCHRONIZATION_SCOPE { WdfSynchronizationScopeInvalid = 0,
    WdfSynchronizationScopeInheritFromParent = 1, WdfSynchronizationScopeDevice = 2,
    WdfSynchronizationScopeQueue = 3, WdfSynchronizationScopeNone = 4 } WDF_SYNCHRONIZATION_SCOPE;
typedef enum _WDF_IO_QUEUE_DISPATCH_TYPE { WdfIoQueueDispatchInvalid = 0,
    WdfIoQueueDispatchSequential = 1, WdfIoQueueDispatchParallel = 2,
    WdfIoQueueDispatchManual = 3, WdfIoQueueDispatchMax = 4 } WDF_IO_QUEUE_DISPATCH_TYPE;
typedef enum _WDF_FILEOBJECT_CLASS { WdfFileObjectInvalid = 0,
    WdfFileObjectNotRequired = 1, WdfFileObjectWdfCanUseFsContext = 2,
    WdfFileObjectWdfCanUseFsContext2 = 3, WdfFileObjectWdfCannotUseFsContexts = 4,
    WdfFileObjectCanBeOptional = 0x8000000 } WDF_FILEOBJECT_CLASS;
#define WdfDriverInitNonPnpDriver      0x00000001u
#define WdfDriverInitNoDispatchOverride 0x00000002u

#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define WDF_NO_SEND_OPTIONS NULL
#define WDF_NO_HANDLE NULL

// ---- APIs (empty-parameter declarations: call arguments unchecked) ----
DECL0(NTSTATUS, FwpmEngineOpen0); DECL0(NTSTATUS, FwpmEngineClose0);
DECL0(NTSTATUS, FwpmTransactionBegin0); DECL0(NTSTATUS, FwpmTransactionCommit0); DECL0(NTSTATUS, FwpmTransactionAbort0);
DECL0(NTSTATUS, FwpmProviderAdd0); DECL0(NTSTATUS, FwpmProviderDeleteByKey0);
DECL0(NTSTATUS, FwpmSubLayerAdd0); DECL0(NTSTATUS, FwpmCalloutAdd0); DECL0(NTSTATUS, FwpmCalloutDeleteById0);
DECL0(NTSTATUS, FwpmFilterAdd0); DECL0(NTSTATUS, FwpmFilterDeleteById0);
DECL0(NTSTATUS, FwpmBfeStateSubscribeChanges0); DECL0(NTSTATUS, FwpmBfeStateUnsubscribeChanges0); DECL0(NTSTATUS, FwpmBfeStateGet0);
DECL0(NTSTATUS, FwpsCalloutRegister0); DECL0(NTSTATUS, FwpsCalloutRegister1);
DECL0(NTSTATUS, FwpsCalloutUnregisterById0); DECL0(NTSTATUS, FwpsCalloutUnregisterByKey0);
DECL0(NTSTATUS, FwpsFlowAssociateContext0); DECL0(NTSTATUS, FwpsFlowRemoveContext0);
DECL0(NTSTATUS, FwpsCopyStreamDataToBuffer0);
DECL0(NTSTATUS, FwpsInjectionHandleCreate0); DECL0(NTSTATUS, FwpsInjectionHandleDestroy0);
DECL0(NTSTATUS, FwpsInjectNetworkReceiveAsync0); DECL0(NTSTATUS, FwpsInjectForwardAsync0); DECL0(NTSTATUS, FwpsInjectNetworkSendAsync0);
DECL0(NTSTATUS, FwpsAllocateNetBufferAndNetBufferList0); DECL0(VOID, FwpsFreeNetBufferList0);
DECL0(UINT32, FwpsQueryPacketInjectionState0);
DECL0(PVOID, NdisAllocateNetBufferListPool); DECL0(PVOID, NdisAllocateNetBufferPool);
DECL0(VOID, NdisFreeNetBufferListPool); DECL0(VOID, NdisFreeNetBufferPool);
DECL0(PUCHAR, NdisGetDataBuffer); DECL0(NTSTATUS, NdisAdvanceNetBufferDataStart); DECL0(NTSTATUS, NdisRetreatNetBufferDataStart);
DECL0(NTSTATUS, RtlGetVersion); DECL0(LARGE_INTEGER, KeQueryPerformanceCounter);
DECL0(VOID, RtlInitUnicodeString); DECL0(VOID, RtlCopyUnicodeString); DECL0(BOOLEAN, RtlPrefixUnicodeString);
DECL0(PVOID, ExAllocatePoolWithTag); DECL0(VOID, ExFreePoolWithTag); DECL0(NTSTATUS, ExUuidCreate);
DECL0(KIRQL, KeAcquireSpinLockRaiseToDpc); DECL0(VOID, KeReleaseSpinLock);
DECL0(VOID, KeAcquireInStackQueuedSpinLock); DECL0(VOID, KeReleaseInStackQueuedSpinLock);
DECL0(KIRQL, ExAcquireSpinLockExclusive); DECL0(VOID, ExReleaseSpinLockExclusive);
DECL0(KIRQL, ExAcquireSpinLockShared); DECL0(VOID, ExReleaseSpinLockShared);
DECL0(NTSTATUS, ExInitializeResourceLite); DECL0(VOID, ExDeleteResourceLite);
DECL0(VOID, KeInitializeEvent); DECL0(LONG, KeSetEvent); DECL0(VOID, KeClearEvent); DECL0(LONG, KeWaitForSingleObject);
DECL0(LONG, KeWaitForMultipleObjects);
DECL0(NTSTATUS, WdfIoQueueReadyNotify);
typedef struct _SK_SHIM_KMUTEX { LONG64 x[5]; } KMUTEX, *PKMUTEX; // shim opaque placeholder (real KMUTEX is 40B)
DECL0(VOID, KeInitializeMutex); DECL0(LONG, KeReleaseMutex);
DECL0(PVOID, IoGetCurrentProcess); DECL0(HANDLE, PsGetCurrentThreadId); DECL0(HANDLE, PsGetProcessId);
DECL0(NTSTATUS, PsCreateSystemThread); DECL0(VOID, KeStackAttachProcess); DECL0(VOID, KeUnstackDetachProcess);
DECL0(NTSTATUS, ObReferenceObjectByHandle); DECL0(VOID, ObfDereferenceObject); DECL0(VOID, ObfReferenceObject);
DECL0(NTSTATUS, ZwClose); DECL0(NTSTATUS, ZwWaitForSingleObject); DECL0(PVOID, MmGetSystemRoutineAddress);
DECL0(PVOID, MmMapLockedPagesSpecifyCache);
DECL0(NTSTATUS, IoCreateDevice); DECL0(VOID, IoDeleteDevice); DECL0(NTSTATUS, IoCreateSymbolicLink);
DECL0(PVOID, IoAllocateWorkItem); DECL0(VOID, IoFreeWorkItem); DECL0(VOID, IoQueueWorkItem);
DECL0(VOID, IoQueueWorkItemEx);
DECL0(UINT32, FwpsInjectStreamSendAsync0);
// WDF direct-call forms (some restored code calls via function tables, some direct)
DECL0(NTSTATUS, WdfDriverCreate); DECL0(NTSTATUS, WdfDeviceCreate); DECL0(NTSTATUS, WdfIoQueueCreate);
DECL0(PWDFDEVICE_INIT, WdfControlDeviceInitAllocate); DECL0(VOID, WdfDeviceInitSetDeviceType);
DECL0(VOID, WdfDeviceInitSetIoType); DECL0(NTSTATUS, WdfDeviceInitAssignName);
DECL0(VOID, WdfDeviceInitSetFileObjectConfig); DECL0(VOID, WdfDeviceInitSetIoInCallerContextCallback);
DECL0(VOID, WdfDeviceInitFree); DECL0(VOID, WdfControlFinishInitializing);
DECL0(NTSTATUS, WdfDeviceCreateSymbolicLink); DECL0(PDEVICE_OBJECT, WdfDeviceWdmGetDeviceObject);
DECL0(NTSTATUS, WdfWorkItemCreate); DECL0(VOID, WdfWorkItemEnqueue);
DECL0(NTSTATUS, WdfRequestRetrieveInputBuffer); DECL0(NTSTATUS, WdfRequestRetrieveOutputBuffer);
DECL0(NTSTATUS, WdfRequestRetrieveOutputWdmMdl); DECL0(VOID, WdfRequestCompleteWithInformation);
DECL0(VOID, WdfRequestComplete); DECL0(NTSTATUS, WdfIoQueueRetrieveNextRequest);
DECL0(VOID, WdfObjectDereferenceActual); DECL0(VOID, WdfObjectReferenceActual);
DECL0(PVOID, WdfObjectGetTypedContextWorker);
DECL0(NTSTATUS, WdfRequestSend); DECL0(NTSTATUS, WdfDeviceEnqueueRequest);
DECL0(NTSTATUS, WdfDeviceCreateDeviceInterface);

// ---- Needed by the shinken_runtime / shinken_event / shinken_driver units ----
DECL0(VOID, WdfWorkItemFlush); DECL0(VOID, WdfObjectDelete); DECL0(VOID, WdfIoQueuePurge);
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_IHVDRIVER_ID 77
DECL0(VOID, DbgPrint); DECL0(ULONG, DbgPrintEx);
DECL0(NTSTATUS, KeDelayExecutionThread);

// Doubly-linked list inlines (WDK semantics; restored code expands them as
// pointers, new units use the standard forms)
static __inline VOID InitializeListHead(PLIST_ENTRY ListHead) {
    ListHead->Flink = ListHead->Blink = ListHead;
}
static __inline BOOLEAN IsListEmpty(const LIST_ENTRY *ListHead) {
    return (BOOLEAN)(ListHead->Flink == ListHead);
}
static __inline VOID RemoveEntryList(PLIST_ENTRY Entry) {
    Entry->Blink->Flink = Entry->Flink;
    Entry->Flink->Blink = Entry->Blink;
}
static __inline PLIST_ENTRY RemoveHeadList(PLIST_ENTRY ListHead) {
    PLIST_ENTRY e = ListHead->Flink;
    ListHead->Flink = e->Flink;
    e->Flink->Blink = ListHead;
    return e;
}
static __inline VOID InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry) {
    Entry->Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    ListHead->Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

// Atomics/builtins: _Interlocked* and _mm_lfence are clang builtins, not declared
#ifndef __cplusplus
typedef int bool;
#endif

#ifdef __cplusplus
}
#endif
