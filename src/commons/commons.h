#pragma once

// Ensure we have the right environment
#ifdef _KERNEL_MODE1
    // Kernel mode - types are already defined
#include <ntddk.h>
typedef LONG NTSTATUS;
typedef UCHAR UINT8;
typedef USHORT UINT16;
typedef ULONGLONG UINT64;
#else
    // User mode - need to define kernel types
#include <Windows.h>
#endif

// Driver and device names
#define NETMON_DEVICE_NAME      L"\\Device\\NetMonPOC"
#define NETMON_SYMLINK_NAME     L"\\??\\NetMonPOC"
#define NETMON_USER_DEVICE_NAME L"\\\\.\\NetMonPOC"

// IOCTL definitions
#define FILE_DEVICE_NETMON      0x8000
#define NETMON_IOCTL_BASE       0x800

// Method: METHOD_BUFFERED, Access: FILE_ANY_ACCESS
#define IOCTL_NETMON_GET_EVENT  CTL_CODE(FILE_DEVICE_NETMON, NETMON_IOCTL_BASE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETMON_CLEAR_EVENTS CTL_CODE(FILE_DEVICE_NETMON, NETMON_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETMON_GET_STATS CTL_CODE(FILE_DEVICE_NETMON, NETMON_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Configuration constants
#define NETMON_MAX_EVENTS       1000
#define NETMON_MAX_PATH         260
#define NETMON_MAX_CAPTURE_SIZE 256    // Maximum bytes to capture per packet

// Ensure structure packing is consistent
#pragma pack(push, 1)

// Network event types that we monitor
typedef enum _NETWORK_EVENT_TYPE
{
    EVENT_TYPE_PACKET_DATA = 0,      // Raw packet data (UDP/ICMP/etc)
    EVENT_TYPE_STREAM_DATA,          // TCP stream data (reassembled)
    EVENT_TYPE_OUTBOUND_CONNECT,     // Outbound connection attempt
    EVENT_TYPE_INBOUND_ACCEPT,       // Inbound connection accepted
    EVENT_TYPE_LISTEN                // Application listening on port

} NETWORK_EVENT_TYPE, * PNETWORK_EVENT_TYPE;

// IP Protocol numbers
#define IPPROTO_ICMP    1
#define IPPROTO_IGMP    2
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_GRE     47
#define IPPROTO_ESP     50
#define IPPROTO_AH      51

// TCP Flags
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20


// Structure to hold network event information
// This is shared between kernel and user mode
typedef struct _NETWORK_EVENT_INFO
{
    NETWORK_EVENT_TYPE EventType;        // Type of network event
    LARGE_INTEGER TimeStamp;             // When the event occurred

    // Connection information
    UINT32 LocalAddress;                 // Local IP address (network byte order)
    UINT32 RemoteAddress;                // Remote IP address (network byte order)
    UINT16 LocalPort;                    // Local port (host byte order)
    UINT16 RemotePort;                   // Remote port (host byte order)
    UINT8 Protocol;                      // IP protocol (6=TCP, 17=UDP, etc.)
    BOOLEAN IsInbound;                   // Traffic direction
    UINT8 Reserved[2];                   // Padding for alignment

    // Process information (available only from ALE layers)
    UINT64 ProcessId;                    // Process ID that initiated the connection
    WCHAR ProcessPath[NETMON_MAX_PATH];  // Full path to the process executable

    // Additional information
    ULONG DataLength;                    // Size of data in packet (if applicable)
    CHAR ApplicationProtocol[64];        // Detected application protocol

    // Captured packet data
    UINT32 CapturedDataLength;           // Length of captured data
    UINT8 CapturedData[NETMON_MAX_CAPTURE_SIZE]; // First N bytes of packet/stream data

} NETWORK_EVENT_INFO, * PNETWORK_EVENT_INFO;

// IOCTL request structure - sent from user mode
typedef struct _NETMON_GET_EVENTS_REQUEST
{
    ULONG MaxEvents;                     // Maximum events to retrieve

} NETMON_GET_EVENTS_REQUEST, * PNETMON_GET_EVENTS_REQUEST;

// IOCTL response structure - sent to user mode
// Note: Uses flexible array member for variable-length data
typedef struct _NETMON_GET_EVENTS_RESPONSE
{
    ULONG EventCount;                    // Number of events returned
    NETWORK_EVENT_INFO Events[1];        // Variable-length array of events

} NETMON_GET_EVENTS_RESPONSE, * PNETMON_GET_EVENTS_RESPONSE;

// Statistics structure
typedef struct _NETMON_STATISTICS
{
    UINT64 TotalPackets;                 // Total packets processed
    UINT64 TotalConnections;             // Total connections monitored
    UINT64 EventsDropped;                // Events dropped due to buffer full
    UINT64 StartTime;                    // When monitoring started (tick count)

    // Per-type counters
    UINT64 PacketDataEvents;
    UINT64 StreamDataEvents;
    UINT64 OutboundConnectEvents;
    UINT64 InboundAcceptEvents;
    UINT64 ListenEvents;

    // Protocol counters
    UINT64 TcpPackets;
    UINT64 UdpPackets;
    UINT64 IcmpPackets;
    UINT64 OtherPackets;

} NETMON_STATISTICS, * PNETMON_STATISTICS;

// Clear events request/response
typedef struct _NETMON_CLEAR_EVENTS_REQUEST
{
    ULONG Flags;                         // Reserved for future use

} NETMON_CLEAR_EVENTS_REQUEST, * PNETMON_CLEAR_EVENTS_REQUEST;

#pragma pack(pop)

// Helper macros that work in both kernel and user mode
#define NETMON_IP_ADDR_1(addr) ((addr) & 0xFF)
#define NETMON_IP_ADDR_2(addr) (((addr) >>  8) & 0xFF)
#define NETMON_IP_ADDR_3(addr) (((addr) >>  16) & 0xFF)
#define NETMON_IP_ADDR_4(addr) (((addr) >>  24) & 0xFF)

#define NETMON_FORMAT_IP(addr) \
    NETMON_IP_ADDR_1(addr), \
    NETMON_IP_ADDR_2(addr), \
    NETMON_IP_ADDR_3(addr), \
    NETMON_IP_ADDR_4(addr)

// Status codes (subset of NTSTATUS that we use)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST   ((NTSTATUS)0xC0000010L)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#endif

// Calculate the size needed for a response buffer
#define NETMON_RESPONSE_SIZE(count) \
    (FIELD_OFFSET(NETMON_GET_EVENTS_RESPONSE, Events) + \
     sizeof(NETWORK_EVENT_INFO) * (count))

// Helper function to get event type name
inline const char* GetEventTypeName(NETWORK_EVENT_TYPE type)
{
    switch (type) {
    case EVENT_TYPE_PACKET_DATA:      return "PACKET";
    case EVENT_TYPE_STREAM_DATA:      return "STREAM";
    case EVENT_TYPE_OUTBOUND_CONNECT: return "CONNECT";
    case EVENT_TYPE_INBOUND_ACCEPT:   return "ACCEPT";
    case EVENT_TYPE_LISTEN:           return "LISTEN";
    default:                          return "UNKNOWN";
    }
}

// Helper function to get protocol name
inline const char* GetProtocolName(UINT8 protocol)
{
    switch (protocol) {
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_IGMP: return "IGMP";
    case IPPROTO_GRE:  return "GRE";
    case IPPROTO_ESP:  return "ESP";
    case IPPROTO_AH:   return "AH";
    default:           return "???";
    }
}

