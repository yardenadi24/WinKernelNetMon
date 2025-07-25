#include "drv.h"
#include "ntstrsafe.h"

#pragma warning(disable: 4996)

// Event management structure - initialized to zero
EVENT_MANAGER g_EventManager = { 0 };

// WFP engine handle - NULL until we open a session
HANDLE g_EngineHandle = NULL;

// Arrays to store multiple callout and filter IDs
UINT32 g_CalloutIds[4] = { 0 };
UINT64 g_FilterIds[4] = { 0 };
FILTER_REG_INFO g_FiltersInfo[4];

// Device object pointer - set during driver initialization
PDEVICE_OBJECT g_pDeviceObject = NULL;

// Sublayer GUID - all our filters will be added to this sublayer
const GUID WFP_NET_MON_POC_POC_SUBLAYER_GUID =
{ 0x5c4aa8b1, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

// Callout GUIDs - one for each layer we're monitoring
const GUID WFP_NET_MON_POC_CALLOUT_DATAGRAM_DATA_V4_GUID =
{ 0x5c4aa8b3, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_CALLOUT_ALE_AUTH_CONNECT_V4_GUID =
{ 0x5c4aa8b5, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_CALLOUT_ALE_AUTH_RECV_ACCEPT_V4_GUID =
{ 0x5c4aa8b7, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_CALLOUT_ALE_AUTH_LISTEN_V4_GUID =
{ 0x5c4aa8b9, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

// Filter GUIDs - one for each filter we're adding
const GUID WFP_NET_MON_POC_FILTER_DATAGRAM_DATA_V4_GUID =
{ 0x5c4aa8b2, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_FILTER_ALE_AUTH_CONNECT_V4_GUID =
{ 0x5c4aa8b4, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_FILTER_ALE_AUTH_RECV_ACCEPT_V4_GUID =
{ 0x5c4aa8b6, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };

const GUID WFP_NET_MON_POC_FILTER_ALE_AUTH_LISTEN_V4_GUID =
{ 0x5c4aa8b8, 0x82ef, 0x4e23, {0x91, 0xae, 0xe8, 0xf3, 0x5e, 0x46, 0xdf, 0xb2} };


VOID
InitializeFilterInfo()
{
	DbgPrint("[NetMon] Initializing filter info array\n");

	// Clear the array first
	RtlZeroMemory(g_FiltersInfo, sizeof(g_FiltersInfo));

	// =========================================
	// Filter 0: Datagram Data (Raw Packets)
	// =========================================
	g_FiltersInfo[0].layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
	wcscpy_s(g_FiltersInfo[0].name, 100, L"WFP Monitor - Packet Data");
	wcscpy_s(g_FiltersInfo[0].description, 100, L"Monitors all IPv4 traffic");
	g_FiltersInfo[0].type = FWP_ACTION_CALLOUT_TERMINATING;
	g_FiltersInfo[0].calloutKey = WFP_NET_MON_POC_CALLOUT_DATAGRAM_DATA_V4_GUID;
	g_FiltersInfo[0].subLayerKey = WFP_NET_MON_POC_POC_SUBLAYER_GUID;
	g_FiltersInfo[0].filterKey = WFP_NET_MON_POC_FILTER_DATAGRAM_DATA_V4_GUID;
	g_FiltersInfo[0].classifyFunc = ClassifyDatagramFn;

	// =========================================
	// Filter 1: Outbound Connections
	// =========================================
	g_FiltersInfo[1].layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	wcscpy_s(g_FiltersInfo[1].name, 100, L"WFP Monitor - Application outbound connection");
	wcscpy_s(g_FiltersInfo[1].description, 100, L"Monitor all outbound connections of applications");
	g_FiltersInfo[1].type = FWP_ACTION_CALLOUT_TERMINATING;
	g_FiltersInfo[1].calloutKey = WFP_NET_MON_POC_CALLOUT_ALE_AUTH_CONNECT_V4_GUID;
	g_FiltersInfo[1].subLayerKey = WFP_NET_MON_POC_POC_SUBLAYER_GUID;
	g_FiltersInfo[1].filterKey = WFP_NET_MON_POC_FILTER_ALE_AUTH_CONNECT_V4_GUID;
	g_FiltersInfo[1].classifyFunc = ClassifyAleAuthConnectFn;

	// =========================================
	// Filter 2: Inbound Connections
	// =========================================
	g_FiltersInfo[2].layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	wcscpy_s(g_FiltersInfo[2].name, 100, L"WFP Monitor - Application inbound connection");
	wcscpy_s(g_FiltersInfo[2].description, 100, L"Monitor all inbound connections of applications");
	g_FiltersInfo[2].type = FWP_ACTION_CALLOUT_TERMINATING;
	g_FiltersInfo[2].calloutKey = WFP_NET_MON_POC_CALLOUT_ALE_AUTH_RECV_ACCEPT_V4_GUID;
	g_FiltersInfo[2].subLayerKey = WFP_NET_MON_POC_POC_SUBLAYER_GUID;
	g_FiltersInfo[2].filterKey = WFP_NET_MON_POC_FILTER_ALE_AUTH_RECV_ACCEPT_V4_GUID;
	g_FiltersInfo[2].classifyFunc = ClassifyAleAuthRecvAcceptFn;

	// =========================================
	// Filter 3: Listen Operations
	// =========================================
	g_FiltersInfo[3].layerKey = FWPM_LAYER_ALE_AUTH_LISTEN_V4;
	wcscpy_s(g_FiltersInfo[3].name, 100, L"WFP Monitor - Application attempt to listen on a port");
	wcscpy_s(g_FiltersInfo[3].description, 100, L"Monitor all port listening attempts of applications");
	g_FiltersInfo[3].type = FWP_ACTION_CALLOUT_TERMINATING;
	g_FiltersInfo[3].calloutKey = WFP_NET_MON_POC_CALLOUT_ALE_AUTH_LISTEN_V4_GUID;
	g_FiltersInfo[3].subLayerKey = WFP_NET_MON_POC_POC_SUBLAYER_GUID;
	g_FiltersInfo[3].filterKey = WFP_NET_MON_POC_FILTER_ALE_AUTH_LISTEN_V4_GUID;
	g_FiltersInfo[3].classifyFunc = ClassifyAleAuthListenFn;

	// Verify all function pointers are valid
	DbgPrint("[NetMon] Function pointer verification:\n");
	for (int i = 0; i < 4; i++) {
		DbgPrint("  Filter[%d] '%ws': classifyFunc = %p\n",
			i, g_FiltersInfo[i].name, g_FiltersInfo[i].classifyFunc);

		if (g_FiltersInfo[i].classifyFunc == NULL) {
			DbgPrint("  ERROR: NULL function pointer detected!\n");
		}
	}
}

/*
 * Helper Functions Implementation
 */

 // Convert protocol number to human-readable string
PCHAR GetProtocolString(UINT8 protocol)
{
	switch (protocol)
	{
	case 6:  return "TCP";
	case 17: return "UDP";
	case 1:  return "ICMP";
	case 2:  return "IGMP";
	case 47: return "GRE";
	case 50: return "ESP";
	case 51: return "AH";
	default: return "UNKNOWN";
	}
}

// Guess application protocol based on port number
PCHAR GuessApplicationProtocol(UINT16 port, UINT8 protocol)
{
	// Only TCP/UDP have application protocols
	if (protocol != 6 && protocol != 17) {
		return "";
	}

	switch (port) {
		// Web protocols
	case 80:    return " (HTTP)";
	case 443:   return " (HTTPS)";
	case 8080:  return " (HTTP-ALT)";
	case 8443:  return " (HTTPS-ALT)";

		// File transfer
	case 21:    return " (FTP-CTRL)";
	case 20:    return " (FTP-DATA)";
	case 22:    return " (SSH/SFTP)";
	case 445:   return " (SMB/CIFS)";
	case 139:   return " (NetBIOS/SMB)";

		// Email protocols
	case 25:    return " (SMTP)";
	case 587:   return " (SMTP-SUB)";
	case 110:   return " (POP3)";
	case 995:   return " (POP3S)";
	case 143:   return " (IMAP)";
	case 993:   return " (IMAPS)";

		// Remote access
	case 3389:  return " (RDP)";
	case 23:    return " (TELNET)";
	case 5900:  return " (VNC)";

		// Database protocols
	case 3306:  return " (MySQL)";
	case 5432:  return " (PostgreSQL)";
	case 1433:  return " (SQL Server)";
	case 1521:  return " (Oracle)";

		// Other important protocols
	case 53:    return " (DNS)";
	case 67:    return " (DHCP-S)";
	case 68:    return " (DHCP-C)";
	case 123:   return " (NTP)";
	case 161:   return " (SNMP)";
	case 162:   return " (SNMP-TRAP)";

	default:
		if (port >= 49152) return " (DYNAMIC)";
		if (port >= 1024)  return " (USER)";
		return " (SYSTEM)";
	}
}

// Extract process path from metadata
VOID GetProcessPath(
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Out_ PWCHAR processPath,
	_In_ SIZE_T processPathSize)
{
	// At DISPATCH_LEVEL, we must be very careful
	// Just do a simple memory copy if available

	if (processPath == NULL || processPathSize == 0)
		return;

	// Initialize to empty string first
	processPath[0] = L'\0';

	if (inMetaValues->processPath && inMetaValues->processPath->size > 0)
	{
		SIZE_T copySize = min(inMetaValues->processPath->size, processPathSize - sizeof(WCHAR));

		// RtlCopyMemory is safe at DISPATCH_LEVEL
		RtlCopyMemory(processPath, inMetaValues->processPath->data, copySize);

		// Ensure null termination
		processPath[copySize / sizeof(WCHAR)] = L'\0';
	}
}

// Add a network event to our circular buffer
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
	_In_opt_ UINT8 protocol)
{
	KIRQL oldIrql;
	PEVENT_NODE node;

	// Check if event manager is initialized
	if (!g_EventManager.IsInitialized)
		return;

	// Allocate memory for new event node
	node = (PEVENT_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(EVENT_NODE), MEM_TAG);
	if (node == NULL)
		return;

	// Initialize the node
	RtlZeroMemory(node, sizeof(EVENT_NODE));

	// Fill in event information
	node->Event.EventType = Type;
	KeQuerySystemTime(&node->Event.TimeStamp);
	node->Event.LocalAddress = localAddress;
	node->Event.RemoteAddress = remoteAddress;
	node->Event.LocalPort = localPort;
	node->Event.RemotePort = remotePort;
	node->Event.DataLength = dataLength;
	node->Event.IsInbound = isOutbound;
	node->Event.ProcessId = processId;
	node->Event.Protocol = protocol =! 0 ? protocol : ((localPort == 0 && remotePort == 0) ? 0 :
		(Type == EVENT_TYPE_LISTEN ? 6 : 0));  // Assume TCP for listen

	// IRQL-safe string copy for process path
	if (processPath != NULL)
	{
		SIZE_T i;
		for (i = 0; i < (MAX_PATH - 1) && processPath[i] != L'\0'; i++)
		{
			node->Event.ProcessPath[i] = processPath[i];
		}
		node->Event.ProcessPath[i] = L'\0';
	}
	else
	{
		// Simple string assignment without function calls
		WCHAR unknown[] = L"<UNKNOWN>";
		for (int i = 0; i < sizeof(unknown) / sizeof(WCHAR); i++)
		{
			node->Event.ProcessPath[i] = unknown[i];
		}
	}

	if (appProtocol != NULL)
	{
		SIZE_T i;
		for (i = 0; i < 31 && appProtocol[i] != '\0'; i++)
		{
			node->Event.ApplicationProtocol[i] = appProtocol[i];
		}
		node->Event.ApplicationProtocol[i] = '\0';
	}
	else
	{
		node->Event.ApplicationProtocol[0] = '\0';
	}

	// Add event to the list with proper synchronization
	KeAcquireSpinLock(&g_EventManager.EventListLock, &oldIrql);

	// If we've reached max events, remove the oldest
	if (g_EventManager.EventCount >= MAX_EVENTS)
	{
		PLIST_ENTRY pOldEntry = RemoveHeadList(&g_EventManager.ListHead);
		if (pOldEntry != NULL)
		{
			PEVENT_NODE pOldNode = CONTAINING_RECORD(pOldEntry, EVENT_NODE, ListEntry);
			ExFreePoolWithTag(pOldNode, MEM_TAG);
			g_EventManager.EventCount--;
		}
	}

	// Add new event to tail of list
	InsertTailList(&g_EventManager.ListHead, &node->ListEntry);
	g_EventManager.EventCount++;

	KeReleaseSpinLock(&g_EventManager.EventListLock, oldIrql);
}

/*
 * WFP Classify Functions Implementation
 * These functions are called by WFP to inspect network traffic
 */

 // Classify function for datagram (packet) data
VOID NTAPI ClassifyDatagramFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	NET_BUFFER_LIST* netBufferList = NULL;
	NET_BUFFER* netBuffer = NULL;
	ULONG dataLength = 0;

	// Extract connection information from fixed values
	UINT32 localAddr = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
	UINT8 direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint8;

	BOOLEAN isOutbound = (direction == FWP_DIRECTION_OUTBOUND);

	// Calculate total data size if layer data is available
	if (layerData != NULL)
	{
		netBufferList = (NET_BUFFER_LIST*)layerData;
		netBuffer = netBufferList->FirstNetBuffer;

		while (netBuffer != NULL)
		{
			dataLength += netBuffer->DataLength;
			netBuffer = netBuffer->Next;
		}
	}

	// Try to identify application protocol
	PCHAR appProtocol = GuessApplicationProtocol(
		isOutbound ? remotePort : localPort,
		protocol
	);

	// Log the event
	DbgPrint("[DATAGRAM_DATA] %s %s %d.%d.%d.%d:%d %s %d.%d.%d.%d:%d %s [%lu Bytes]\n",
		GetProtocolString(protocol),
		isOutbound ? "OUT" : "IN",
		(localAddr & 0xFF), ((localAddr >> 8) & 0xFF),
		((localAddr >> 16) & 0xFF), ((localAddr >> 24) & 0xFF),
		localPort,
		isOutbound ? "->" : "<-",
		(remoteAddr & 0xFF), ((remoteAddr >> 8) & 0xFF),
		((remoteAddr >> 16) & 0xFF), ((remoteAddr >> 24) & 0xFF),
		remotePort,
		appProtocol,
		dataLength
	);

	// Add event to our buffer
	AddNetworkEvent(
		EVENT_TYPE_PACKET_DATA,
		localAddr,
		remoteAddr,
		localPort,
		remotePort,
		isOutbound,
		0,  // No process info at this layer
		NULL,
		dataLength,
		appProtocol,
		protocol
	);

	// IMPORTANT: We must permit the packet to continue
	classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Classify function for outbound connection attempts
VOID NTAPI ClassifyAleAuthConnectFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	WCHAR processPath[MAX_PATH] = { 0 };

	// Extract connection information
	UINT32 localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

	// Get process information
	UINT64 processId = inMetaValues->processId;
	GetProcessPath(inMetaValues, processPath, sizeof(processPath));

	PCHAR appProto = GuessApplicationProtocol(remotePort, protocol);

	// Extract just the process name from full path
	PWCHAR processName = wcsrchr(processPath, L'\\');
	if (processName) processName++; else processName = processPath;

	DbgPrint("[ALE_AUTH_CONNECT] Process %llu attempting %s connection%s\n",
		processId,
		GetProtocolString(protocol),
		appProto);
	DbgPrint("  From: %d.%d.%d.%d:%d To: %d.%d.%d.%d:%d\n",
		(localAddr & 0xFF), ((localAddr >> 8) & 0xFF),
		((localAddr >> 16) & 0xFF), ((localAddr >> 24) & 0xFF),
		localPort,
		(remoteAddr & 0xFF), ((remoteAddr >> 8) & 0xFF),
		((remoteAddr >> 16) & 0xFF), ((remoteAddr >> 24) & 0xFF),
		remotePort);

	// Add event
	AddNetworkEvent(
		EVENT_TYPE_OUTBOUND_CONNECT,
		localAddr,
		remoteAddr,
		localPort,
		remotePort,
		TRUE,  // Always outbound for AUTH_CONNECT
		processId,
		processPath,
		0,
		appProto,
		protocol
	);

	// Permit the connection
	classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Classify function for inbound connection acceptance
VOID NTAPI ClassifyAleAuthRecvAcceptFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	WCHAR processPath[MAX_PATH] = { 0 };

	// Extract connection information
	UINT32 localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;

	// Get process information
	UINT64 processId = inMetaValues->processId;
	GetProcessPath(inMetaValues, processPath, sizeof(processPath));

	// Check if this is a loopback connection
	BOOLEAN isLoopback = (localAddr == remoteAddr) || (localAddr == 0x0100007F); // 127.0.0.1

	PCHAR appProto = GuessApplicationProtocol(localPort, protocol);

	// Extract process name
	PWCHAR processName = wcsrchr(processPath, L'\\');
	if (processName) processName++; else processName = processPath;

	DbgPrint("[ALE_RECV_ACCEPT] Process %llu receiving %s connection%s%s\n",
		processId,
		GetProtocolString(protocol),
		appProto,
		isLoopback ? " (LOOPBACK)" : "");
	DbgPrint("  From: %d.%d.%d.%d:%d To: %d.%d.%d.%d:%d\n",
		(remoteAddr & 0xFF), ((remoteAddr >> 8) & 0xFF),
		((remoteAddr >> 16) & 0xFF), ((remoteAddr >> 24) & 0xFF),
		remotePort,
		(localAddr & 0xFF), ((localAddr >> 8) & 0xFF),
		((localAddr >> 16) & 0xFF), ((localAddr >> 24) & 0xFF),
		localPort);

	// Add event
	AddNetworkEvent(
		EVENT_TYPE_INBOUND_ACCEPT,
		localAddr,
		remoteAddr,
		localPort,
		remotePort,
		FALSE,  // Always inbound for RECV_ACCEPT
		processId,
		processPath,
		0,
		appProto,
		protocol
	);

	// Permit the incoming connection
	classifyOut->actionType = FWP_ACTION_PERMIT;
}

// Classify function for socket listen operations
VOID NTAPI ClassifyAleAuthListenFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER0* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	WCHAR processPath[MAX_PATH] = { 0 };

	// Extract listen information
	UINT32 localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT].value.uint16;

	// Listen is always TCPS
	UINT8 protocol = 6;

	// Get process information
	UINT64 processId = inMetaValues->processId;
	GetProcessPath(inMetaValues, processPath, sizeof(processPath));

	// Determine if listening on all interfaces
	PCHAR listenScope = (localAddr == 0) ? "ALL INTERFACES" : "SPECIFIC";

	// Extract process name
	PWCHAR processName = wcsrchr(processPath, L'\\');
	if (processName) processName++; else processName = processPath;

	DbgPrint("[ALE_LISTEN] Process %llu starting %s listener\n",
		processId,
		GetProtocolString(protocol));
	DbgPrint("  Address: %s (%d.%d.%d.%d), Port: %d\n",
		listenScope,
		(localAddr & 0xFF), ((localAddr >> 8) & 0xFF),
		((localAddr >> 16) & 0xFF), ((localAddr >> 24) & 0xFF),
		localPort);

	// Add event
	AddNetworkEvent(
		EVENT_TYPE_LISTEN,
		localAddr,
		0,  // No remote address for listen
		localPort,
		0,  // No remote port for listen
		FALSE,
		processId,
		processPath,
		0,
		"TCP",  // Listen is always TCP,
		protocol
	);

	// Permit the listen operation
	classifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS
DeviceClose(
	_In_  PDEVICE_OBJECT* DeviceObject,
	_Inout_  PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, FALSE);
	return STATUS_SUCCESS;
}


NTSTATUS
DeviceCreate(
	_In_  PDEVICE_OBJECT* DeviceObject,
	_Inout_  PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS
DeviceIoControl(
	_In_  PDEVICE_OBJECT* DeviceObject,
	_Inout_  PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, FALSE);
	return STATUS_SUCCESS;
}

/*
 * Device I/O Control Handlers
 */

NTSTATUS DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytesReturned = 0;

	// Get the current I/O stack location
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	// Get input/output buffers (using METHOD_BUFFERED)
	PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;

	ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (ioCode)
	{
	case IOCTL_NETMON_GET_EVENT:
	{
		PNETMON_GET_EVENTS_REQUEST request;
		PNETMON_GET_EVENTS_RESPONSE response;

		// Validate input buffer
		if (inputBufferLength < sizeof(NETMON_GET_EVENTS_REQUEST))
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		request = (PNETMON_GET_EVENTS_REQUEST)inputBuffer;
		response = (PNETMON_GET_EVENTS_RESPONSE)outputBuffer;

		// Check if event manager is initialized
		if (!g_EventManager.IsInitialized)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_EventManager.EventListLock, &oldIrql);

		// Calculate how many events we can return
		ULONG count = 0;
		ULONG maxEvents = min(request->MaxEvents, g_EventManager.EventCount);

		// Calculate required buffer size
		ULONG requiredSize = FIELD_OFFSET(NETMON_GET_EVENTS_RESPONSE, Events) +
			sizeof(NETWORK_EVENT_INFO) * maxEvents;

		if (outputBufferLength < requiredSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			bytesReturned = sizeof(NETMON_GET_EVENTS_RESPONSE);  // Tell caller minimum size
			KeReleaseSpinLock(&g_EventManager.EventListLock, oldIrql);
			break;
		}

		// Copy events from our list to the output buffer
		PLIST_ENTRY pListEntry = NULL;
		PEVENT_NODE pNode = NULL;

		while (!IsListEmpty(&g_EventManager.ListHead) && count < maxEvents)
		{
			// Remove from head of list (oldest events first)
			pListEntry = RemoveHeadList(&g_EventManager.ListHead);
			pNode = CONTAINING_RECORD(pListEntry, EVENT_NODE, ListEntry);

			// Copy event to output buffer
			RtlCopyMemory(&response->Events[count], &pNode->Event, sizeof(NETWORK_EVENT_INFO));
			count++;

			// Free the node
			ExFreePoolWithTag(pNode, MEM_TAG);
			g_EventManager.EventCount--;
		}

		KeReleaseSpinLock(&g_EventManager.EventListLock, oldIrql);

		// Set the actual number of events returned
		response->EventCount = count;
		bytesReturned = FIELD_OFFSET(NETMON_GET_EVENTS_RESPONSE, Events) +
			sizeof(NETWORK_EVENT_INFO) * count;

		DbgPrint("[NetMon] IOCTL_GET_EVENT: Returned %lu events\n", count);
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("[NetMon] Unknown IOCTL: 0x%08X\n", ioCode);
	}

	// Complete the IRP
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

// WFP notification callback
NTSTATUS
NTAPI
NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER0* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	// We don't need to handle filter notifications for this simple monitor
	return STATUS_SUCCESS;
}

// WFP flow delete callback
VOID NTAPI FlowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);

	// We're not maintaining per-flow state, so nothing to clean up
}

/*
 * Driver Unload Routine
 */
VOID UnloadNetMon(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(SYM_LINK_NAME);

	DbgPrint("[NetMon] Driver unloading...\n");

	// CRITICAL: Unregister system callouts BEFORE cleaning up engine objects
	for (int i = 0; i < 4; i++)
	{
		NTSTATUS status = STATUS_SUCCESS;
		if (g_CalloutIds[i] != 0)
		{
			status = FwpsCalloutUnregisterById0(g_CalloutIds[i]);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[NetMon] Failed to unregister filter %d: 0x%08X\n", i, status);
			}
			g_CalloutIds[i] = 0;
		}
	}

	// Clean up WFP objects in reverse order
	if (g_EngineHandle != NULL)
	{
		NTSTATUS status;

		// Start a transaction for cleanup
		status = FwpmTransactionBegin(g_EngineHandle, 0);
		if (NT_SUCCESS(status))
		{
			// 1. Delete filters first (they depend on callouts)
			for (int i = 0; i < 4; i++)
			{
				if (g_FilterIds[i] != 0)
				{
					status = FwpmFilterDeleteById(g_EngineHandle, g_FilterIds[i]);
					if (!NT_SUCCESS(status))
					{
						DbgPrint("[NetMon] Failed to delete filter %d: 0x%08X\n", i, status);
					}
					g_FilterIds[i] = 0;
				}
			}

			// 2. Delete callouts from the engine
			for (int i = 0; i < 4; i++)
			{
				status = FwpmCalloutDeleteByKey(g_EngineHandle, &g_FiltersInfo[i].calloutKey);
				if (!NT_SUCCESS(status) && status != STATUS_FWP_NOT_FOUND)
				{
					DbgPrint("[NetMon] Failed to delete callout %d from engine: 0x%08X\n", i, status);
				}
			}

			// 3. Delete the sublayer
			status = FwpmSubLayerDeleteByKey(g_EngineHandle, &WFP_NET_MON_POC_POC_SUBLAYER_GUID);
			if (!NT_SUCCESS(status) && status != STATUS_FWP_NOT_FOUND)
			{
				DbgPrint("[NetMon] Failed to delete sublayer: 0x%08X\n", status);
			}

			// Commit the cleanup
			status = FwpmTransactionCommit(g_EngineHandle);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[NetMon] Failed to commit cleanup transaction: 0x%08X\n", status);
				FwpmTransactionAbort(g_EngineHandle);
			}
		}

		// Close the engine handle
		FwpmEngineClose(g_EngineHandle);
		g_EngineHandle = NULL;
	}

	// Unregister callouts from the system
	for (int i = 0; i < 4; i++)
	{
		if (g_CalloutIds[i] != 0)
		{
			FwpsCalloutUnregisterById(g_CalloutIds[i]);
			g_CalloutIds[i] = 0;
		}
	}

	// Clean up event list
	if (g_EventManager.IsInitialized)
	{
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_EventManager.EventListLock, &oldIrql);

		// Free all remaining events
		while (!IsListEmpty(&g_EventManager.ListHead))
		{
			PLIST_ENTRY pEntry = RemoveHeadList(&g_EventManager.ListHead);
			if (pEntry != NULL)
			{
				PEVENT_NODE node = CONTAINING_RECORD(pEntry, EVENT_NODE, ListEntry);
				ExFreePoolWithTag(node, MEM_TAG);
			}
		}

		g_EventManager.EventCount = 0;
		g_EventManager.IsInitialized = FALSE;

		KeReleaseSpinLock(&g_EventManager.EventListLock, oldIrql);
	}

	// Delete device and symbolic link
	if (pDriverObject->DeviceObject)
	{
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(pDriverObject->DeviceObject);
	}

	DbgPrint("[NetMon] Driver unloaded successfully\n");
}

/*
 * Driver Entry Point
 */
extern "C"
NTSTATUS DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(SYM_LINK_NAME);
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	PDEVICE_OBJECT pDeviceObject = NULL;
	BOOLEAN engineOpened = FALSE;
	BOOLEAN transactionStarted = FALSE;

	DbgPrint("\n[NetMon] ===== Network Monitor Driver Loading =====\n");

	InitializeFilterInfo();

	do
	{
		// Create device object
		status = IoCreateDevice(
			pDriverObject,
			0,                              // No device extension
			&deviceName,
			FILE_DEVICE_UNKNOWN,
			0,                              // No special characteristics
			FALSE,                          // Not exclusive
			&pDeviceObject
		);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to create device: 0x%08X\n", status);
			break;
		}

		// Store device object globally - CRITICAL!
		g_pDeviceObject = pDeviceObject;

		// Create symbolic link for user-mode access
		status = IoCreateSymbolicLink(&symLinkName, &deviceName);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to create symbolic link: 0x%08X\n", status);
			break;
		}

		DbgPrint("[NetMon] Device created successfully\n");

		/*
		 * WFP Initialization
		 */

		 // Create a session with the WFP engine
		FWPM_SESSION session = { 0 };
		session.displayData.name = L"WFP NetMon Session";
		session.displayData.description = L"Session for network monitoring";

		status = FwpmEngineOpen(
			NULL,                           // Local machine
			RPC_C_AUTHN_WINNT,             // Windows authentication
			NULL,                           // Default authentication
			&session,                       // Session parameters
			&g_EngineHandle                // Receives engine handle
		);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to open WFP engine: 0x%08X\n", status);
			break;
		}

		engineOpened = TRUE;
		DbgPrint("[NetMon] WFP engine opened successfully\n");

		// Begin transaction for adding WFP objects
		status = FwpmTransactionBegin(g_EngineHandle, 0);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to begin transaction: 0x%08X\n", status);
			break;
		}
		transactionStarted = TRUE;

		// Try to delete existing sublayer (in case of previous unclean shutdown)
		FwpmSubLayerDeleteByKey(g_EngineHandle, &WFP_NET_MON_POC_POC_SUBLAYER_GUID);

		// Add sublayer
		FWPM_SUBLAYER subLayer = { 0 };
		subLayer.subLayerKey = WFP_NET_MON_POC_POC_SUBLAYER_GUID;
		subLayer.displayData.name = L"WFP Network Monitor Sublayer";
		subLayer.displayData.description = L"Sublayer for network monitoring filters";
		subLayer.weight = 0x100;  // Medium priority

		status = FwpmSubLayerAdd(g_EngineHandle, &subLayer, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to add sublayer: 0x%08X\n", status);
			break;
		}

		DbgPrint("[NetMon] Sublayer added successfully\n");

		// Register callouts and filters
		for (int i = 0; i < 4; i++)
		{
			PFILTER_REG_INFO pFilterInfo = &g_FiltersInfo[i];

			DbgPrint("\n[NetMon] Registering callout %d: %ws\n", i, pFilterInfo->name);

			// Delete any existing callout with same GUID
			FwpmCalloutDeleteByKey(g_EngineHandle, &pFilterInfo->calloutKey);

			// Step 1: Register callout with the system
			FWPS_CALLOUT0 callout = { 0 };
			callout.calloutKey = pFilterInfo->calloutKey;
			callout.classifyFn = pFilterInfo->classifyFunc;
			callout.notifyFn = NotifyFn;
			callout.flowDeleteFn = FlowDeleteFn;
			callout.flags = 0;

			DbgPrint("[NetMon] About to register: DevObj=%p, ClassifyFn=%p\n",
				pDeviceObject, pFilterInfo->classifyFunc);

			status = FwpsCalloutRegister0(pDeviceObject, &callout, &g_CalloutIds[i]);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[NetMon] Failed to register callout with system: 0x%08X\n", status);
				continue;
			}

			DbgPrint("[NetMon] System registration OK, ID=%u\n", g_CalloutIds[i]);

			// Step 2: Add callout to the filter engine
			FWPM_CALLOUT mCallout = { 0 };
			mCallout.calloutKey = pFilterInfo->calloutKey;
			mCallout.displayData.name = pFilterInfo->name;
			mCallout.displayData.description = pFilterInfo->description;
			mCallout.applicableLayer = pFilterInfo->layerKey;
			mCallout.flags = 0;

			status = FwpmCalloutAdd(g_EngineHandle, &mCallout, NULL, &g_CalloutIds[i]);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[NetMon] Failed to add callout to engine: 0x%08X\n", status);

				// Unregister from system
				FwpsCalloutUnregisterById(g_CalloutIds[i]);
				g_CalloutIds[i] = 0;
				continue;
			}

			DbgPrint("[NetMon] Engine registration OK\n");

			// Step 3: Add filter
			FWPM_FILTER filter = { 0 };
			filter.layerKey = pFilterInfo->layerKey;
			filter.displayData.name = pFilterInfo->name;
			filter.displayData.description = pFilterInfo->description;
			filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
			filter.action.calloutKey = pFilterInfo->calloutKey;
			filter.subLayerKey = pFilterInfo->subLayerKey;
			filter.weight.type = FWP_EMPTY;  // Auto-weight

			status = FwpmFilterAdd(g_EngineHandle, &filter, NULL, &g_FilterIds[i]);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[NetMon] Failed to add filter: 0x%08X\n", status);
				// Continue - callout is still registered
			}
			else
			{
				DbgPrint("[NetMon] Filter added successfully, ID=%llu\n", g_FilterIds[i]);
			}
		}

		// Commit transaction
		status = FwpmTransactionCommit(g_EngineHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[NetMon] Failed to commit transaction: 0x%08X\n", status);
			break;
		}
		transactionStarted = FALSE;

		DbgPrint("[NetMon] WFP registration completed successfully\n");

		// Initialize event manager
		RtlZeroMemory(&g_EventManager, sizeof(g_EventManager));
		InitializeListHead(&g_EventManager.ListHead);
		KeInitializeSpinLock(&g_EventManager.EventListLock);
		g_EventManager.IsInitialized = TRUE;

		// Set up driver dispatch routines
		pDriverObject->DriverUnload = UnloadNetMon;
		pDriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;

		DbgPrint("[NetMon] ===== Network Monitor Driver Loaded Successfully =====\n\n");
		return STATUS_SUCCESS;

	} while (FALSE);

	/*
	 * Cleanup on failure
	 */

	DbgPrint("[NetMon] Initialization failed, cleaning up...\n");

	if (transactionStarted)
	{
		FwpmTransactionAbort(g_EngineHandle);
	}

	if (engineOpened && g_EngineHandle != NULL)
	{
		// CRITICAL: Unregister system callouts BEFORE cleaning up engine objects
		for (int i = 0; i < 4; i++)
		{
			NTSTATUS status1 = STATUS_SUCCESS;
			if (g_CalloutIds[i] != 0)
			{
				status1 = FwpsCalloutUnregisterById0(g_CalloutIds[i]);
				if (!NT_SUCCESS(status1))
				{
					DbgPrint("[NetMon] Failed to unregister filter %d: 0x%08X\n", i, status1);
				}
				g_CalloutIds[i] = 0;
			}
		}

		// 2. Delete callouts from the engine
		for (int i = 0; i < 4; i++)
		{
			status = FwpmCalloutDeleteByKey(g_EngineHandle, &g_FiltersInfo[i].calloutKey);
			if (!NT_SUCCESS(status) && status != STATUS_FWP_NOT_FOUND)
			{
				DbgPrint("[NetMon] Failed to delete callout %d from engine: 0x%08X\n", i, status);
			}
		}

		FwpmEngineClose(g_EngineHandle);
		g_EngineHandle = NULL;
	}

	if (pDeviceObject)
	{
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(pDeviceObject);
		g_pDeviceObject = NULL;
	}

	DbgPrint("[NetMon] Driver failed to load: 0x%08X\n", status);
	return status;
}

