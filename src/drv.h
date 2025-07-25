#pragma once
#include "ntddk.h"

#include <initguid.h>  // MUST be before other includes for GUID initialization

#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ip2string.h>



#define DEVICE_NAME L"\\Device\\NetMonPOC"
#define SYM_LINK_NAME L"\\??\\NetMonPOC"
#define MEM_TAG 'tnvE'
#define FILE_DEVICE_NETMON   0x8000
#define IOCTL_NETMON_GET_EVENT CTL_CODE(FILE_DEVICE_NETMON, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_EVENTS 1000

// Network event types that we monitor
typedef enum _NETWORK_EVENT_TYPE
{
	EVENT_TYPE_PACKET_DATA = 0,      // Raw packet data (from DATAGRAM layer)
	EVENT_TYPE_OUTBOUND_CONNECT,     // Outbound connection attempt
	EVENT_TYPE_INBOUND_ACCEPT,       // Inbound connection accepted
	EVENT_TYPE_LISTEN                // Application listening on port

} NETWORK_EVENT_TYPE, * PNETWORK_EVENT_TYPE;


// Structure to hold network event information
// This is shared between kernel and user mode
typedef struct _NETWORK_EVENT_INFO
{
	NETWORK_EVENT_TYPE EventType;    // Type of network event
	LARGE_INTEGER TimeStamp;         // When the event occurred

	// Connection information
	UINT32 LocalAddress;             // Local IP address (network byte order)
	UINT32 RemoteAddress;            // Remote IP address (network byte order)
	UINT16 LocalPort;                // Local port (host byte order)
	UINT16 RemotePort;               // Remote port (host byte order)
	UINT8 Protocol;                  // IP protocol (6=TCP, 17=UDP, etc.)
	BOOLEAN IsInbound;               // Traffic direction

	// Process information (available only from ALE layers)
	UINT64 ProcessId;                // Process ID that initiated the connection
	WCHAR ProcessPath[MAX_PATH];     // Full path to the process executable

	// Additional information
	ULONG DataLength;                // Size of data in packet (if applicable)
	CHAR ApplicationProtocol[32];    // Guessed application protocol (HTTP, SSH, etc.)

} NETWORK_EVENT_INFO, *PNETWORK_EVENT_INFO;

// Node structure for maintaining a linked list of events
typedef struct _EVENT_NODE
{
	LIST_ENTRY ListEntry;            // Links to next/previous nodes
	NETWORK_EVENT_INFO Event;        // The actual event data

} EVENT_NODE, * PEVENT_NODE;

// Event manager structure - manages the circular buffer of events
typedef struct _EVENT_MANAGER
{
	LIST_ENTRY ListHead;             // Head of the event list
	KSPIN_LOCK EventListLock;        // Spinlock for thread-safe access
	ULONG EventCount;                // Current number of events in list
	BOOLEAN IsInitialized;           // Initialization flag

} EVENT_MANAGER, * PEVENT_MANAGER;

// IOCTL request structure - sent from user mode
typedef struct _NETMON_GET_EVENTS_REQUEST
{
	ULONG MaxEvents;                 // Maximum events to retrieve

} NETMON_GET_EVENTS_REQUEST, * PNETMON_GET_EVENTS_REQUEST;

// IOCTL response structure - sent to user mode
// Note: Uses flexible array member for variable-length data
typedef struct _NETMON_GET_EVENTS_RESPONSE
{
	ULONG EventCount;                // Number of events returned
	NETWORK_EVENT_INFO Events[1];    // Variable-length array of events

} NETMON_GET_EVENTS_RESPONSE, * PNETMON_GET_EVENTS_RESPONSE;

// Structure to hold temporary network event data during classification
typedef struct _NETWORK_EVENT {
	WCHAR ProcessPath[260];          // Process path buffer
	UINT64 ProcessId;                // Process ID
	CHAR LocalAddrString[46];        // String representation of local IP
	CHAR RemoteAddrString[46];       // String representation of remote IP
	UINT16 LocalPort;                // Local port number
	UINT16 RemotePort;               // Remote port number
	UINT8 Protocol;                  // Protocol number
} NETWORK_EVENT, * PNETWORK_EVENT;

/*
 * Function pointer types for WFP callouts
 */
typedef void (*ClassifyFnType)(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
	);
// WFP filter registration information
// This structure holds all the information needed to register a WFP filter
typedef struct _FILTER_REG_INFO
{
	GUID layerKey;                   // WFP layer GUID (e.g., FWPM_LAYER_DATAGRAM_DATA_V4)
	WCHAR name[100];                 // Display name for the filter
	WCHAR description[100];          // Description of what the filter does
	FWP_ACTION_TYPE type;            // Action type (we use FWP_ACTION_CALLOUT_TERMINATING)
	GUID calloutKey;                 // Unique GUID for this callout
	GUID subLayerKey;                // Sublayer GUID (all our filters use the same sublayer)
	GUID filterKey;                  // Unique GUID for this filter
	ClassifyFnType classifyFunc;     // Pointer to the classify function

} FILTER_REG_INFO, * PFILTER_REG_INFO;

// Driver entry point
extern "C"
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
);

VOID
UnloadNetMon(
	PDRIVER_OBJECT pDriverObject
);


// IRP dispatch routines
NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

NTSTATUS
DeviceIoControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

// WFP Classify functions - these inspect network traffic
VOID
NTAPI
ClassifyDatagramFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

VOID
NTAPI
ClassifyAleAuthConnectFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

VOID
NTAPI
ClassifyAleAuthRecvAcceptFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

VOID
NTAPI
ClassifyAleAuthListenFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

// WFP Notification callback - called when filter changes occur
NTSTATUS
NTAPI
NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER0* filter
);

// WFP Flow delete callback - called when a flow is terminated
VOID
NTAPI
FlowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
);

// Event management functions
VOID AddNetworkEvent(
	_In_ NETWORK_EVENT_TYPE Type,
	_In_ UINT32 localAddress,
	_In_ UINT32 remoteAddress,
	_In_ UINT16 localPort,
	_In_ UINT16 remotePort,
	_In_ BOOLEAN isOutbound,
	_In_ UINT64 processId,
	_In_opt_ PCWSTR processPath,
	_In_ ULONG dataLength,
	_In_opt_ PCSTR appProtocol,
	_In_opt_ UINT8 protocol);

// Helper functions
PCHAR GetProtocolString( UINT8 protocol);
PCHAR GuessApplicationProtocol(UINT16 port, UINT8 protocol);


VOID
GetProcessPath(
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Out_ PWCHAR processPath,
	_In_ SIZE_T processPathSize
);