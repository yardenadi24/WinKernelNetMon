#pragma once

#include <Windows.h>
#include <string.h>
#include <fstream>
#include <mutex>
#include <stdlib.h>
#include <vector>
#include <signal.h>
#include <sstream>
#define FILE_DEVICE_NETMON   0x8000
#define IOCTL_NETMON_GET_EVENT CTL_CODE(FILE_DEVICE_NETMON, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_EVENTS 1000
#define DEVICE_NAME L"\\\\.\\NetMonPOC"
#define DEFAULT_LOG_DIR "C:\\NetMonLogs"
#define DEFAULT_MAX_LOG_SIZE (1024 * 1024 * 50) // 50MB
#define DEFAULT_MAX_LOG_FILES 10
#define MAX_EVENTS_PER_POLL 100
#define POLL_INTERVAL_MS 1000

static boolean g_running = false;

typedef enum _NETWORK_EVENT_TYPE
{
	EVENT_TYPE_PACKET_DATA = 0,
	EVENT_TYPE_OUTBOUND_CONNECT,
	EVENT_TYPE_INBOUND_ACCEPT,
	EVENT_TYPE_LISTEN

}NETWORK_EVENT_TYPE, * PNETWORK_EVENT_TYPE;


typedef struct _NETWORK_EVENT_INFO
{

	NETWORK_EVENT_TYPE EventType;
	LARGE_INTEGER TimeStamp;

	UINT32 LocalAddress;
	UINT32 RemoteAddress;
	UINT16 LocalPort;
	UINT16 RemotePort;
	UINT8 Protocol;
	BOOLEAN IsInbound;

	UINT64 ProcessId;
	WCHAR ProcessPath[MAX_PATH];

	ULONG DataLength;
	CHAR ApplicationProtocol[32];

}NETWORK_EVENT_INFO, * PNETWORK_EVENT_INFO;

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

std::string GetCurrentTimeString()
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	char time[64];

	sprintf_s(time, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	return std::string(time);
}

// Helper functions
const char* GetEventTypeName(NETWORK_EVENT_TYPE type) {
	switch (type) {
	case EVENT_TYPE_PACKET_DATA:      return "PACKET";
	case EVENT_TYPE_OUTBOUND_CONNECT: return "CONNECT";
	case EVENT_TYPE_INBOUND_ACCEPT:   return "ACCEPT";
	case EVENT_TYPE_LISTEN:           return "LISTEN";
	default:                          return "UNKNOWN";
	}
}

const char* GetProtocolName(UINT8 protocol) {
	switch (protocol) {
	case 6:   return "TCP";
	case 17:  return "UDP";
	case 1:   return "ICMP";
	case 2:   return "IGMP";
	case 47:  return "GRE";
	case 50:  return "ESP";
	case 51:  return "AH";
	default:  return "???";
	}
}

void FormatIPAddress(UINT32 addr, char* buffer) {
	sprintf_s(buffer, 16, "%d.%d.%d.%d",
		(addr & 0xFF),
		((addr >> 8) & 0xFF),
		((addr >> 16) & 0xFF),
		((addr >> 24) & 0xFF));
}

const WCHAR* GetProcessName(const WCHAR* path) {
	const WCHAR* lastSlash = wcsrchr(path, L'\\'); // wide char search reverse
	return lastSlash ? lastSlash + 1 : path;
}

void SignalHandler(int signal)
{
	if (signal == SIGINT || signal == SIGTERM)
		g_running = false;

}

BOOL
WINAPI
ConsoleCtrlHandler(
	DWORD ctrlType
)
{
	switch (ctrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		printf("\n[SIGNAL] Shutdown signal received\n");
		g_running = false;
		return TRUE;

	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		g_running = false;
		return TRUE;

	default:
		return FALSE;
	}
}

std::string WideToNarrow(const WCHAR* wide) {
	if (!wide) return "";

	int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
	if (size <= 0) return "";

	std::string narrow(size - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, wide, -1, &narrow[0], size, NULL, NULL);

	return narrow;
}

class Logger
{
public:
	bool initialzied = false;
	Logger(
		const std::string& DirectoryName = DEFAULT_LOG_DIR,
		size_t MaxSize = DEFAULT_MAX_LOG_SIZE,
		int MaxFiles = DEFAULT_MAX_LOG_FILES)
		: m_directoryName(DirectoryName),
		m_maxSize(MaxSize),
		m_maxFiles(MaxFiles),
		m_currentSize(0)
	{
		CreateDirectoryA(m_directoryName.c_str(), NULL);
	}
	~Logger() {
		Close();
	}

	bool Initialize()
	{
		std::lock_guard<std::mutex> lock(m_logMutex);

		// Get local time for file name
		SYSTEMTIME st;
		GetLocalTime(&st);

		char fileName[MAX_PATH];
		sprintf_s(
			fileName,
			"%s\\netmon_%04d%02d%02d_%02d%02d%02d.log",
			m_directoryName.c_str(),
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond);

		m_currentLogFile = fileName;

		// Open file
		m_fileStream.open(m_currentLogFile, std::ios::app);
		if (!m_fileStream.is_open())
		{

			printf("Failed to create log file: %s\n", m_currentLogFile.c_str());
			return false;
		}

		// Write header
		m_fileStream << "=== Network monitor log started ... ===" << std::endl;
		m_fileStream << "Time: " << GetCurrentTimeString() << std::endl;
		m_fileStream << "=======================================" << std::endl;
		m_fileStream.flush();

		m_currentSize = static_cast<size_t>(m_fileStream.tellp());

		printf("Logging to: %s\n", m_currentLogFile.c_str());
		initialzied = true;
		return true;
	}

	void Close()
	{
		std::lock_guard<std::mutex> lock(m_logMutex);
		initialzied = false;
		if (m_fileStream.is_open())
		{
			m_fileStream << "=== Network monitoring log ===" << std::endl;
			m_fileStream << "Time: " << GetCurrentTimeString() << std::endl;
			m_fileStream.close();
		}
	}

	void LogMessage(const std::string& message)
	{
		std::lock_guard<std::mutex> lock(m_logMutex);

		if (!m_fileStream.is_open())
			return;

		std::string time = "[" + GetCurrentTimeString() + "] " + message;
		m_fileStream << time << std::endl;
	}

private:


	std::string m_directoryName;
	std::string m_currentLogFile;
	size_t m_maxSize;
	size_t m_currentSize;
	int m_maxFiles;
	std::mutex m_logMutex;
	std::ofstream m_fileStream;
};

class ConsoleColor
{
public:
	HANDLE m_hConsole; // Console handler
	WORD m_origin;

	ConsoleColor(): m_hConsole(GetStdHandle(STD_OUTPUT_HANDLE))
	{
		CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
		GetConsoleScreenBufferInfo(m_hConsole, &consoleInfo);

		m_origin = consoleInfo.wAttributes;
	}

	void Set(WORD attr)
	{
		SetConsoleTextAttribute(m_hConsole, attr);
	}

	void Reset()
	{
		Set(m_origin);
	}

	static WORD GetEventColor(NETWORK_EVENT_TYPE type) {
		switch (type) {
		case EVENT_TYPE_PACKET_DATA:      return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		case EVENT_TYPE_OUTBOUND_CONNECT: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		case EVENT_TYPE_INBOUND_ACCEPT:   return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		case EVENT_TYPE_LISTEN:           return FOREGROUND_RED | FOREGROUND_INTENSITY;
		default:                          return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
		}
	}

};

class NetworkMonitor {
	
private:
	HANDLE hDevice; // NetMon device handle
	ConsoleColor m_console;
	ULONG m_totalProcessed;
	std::string m_sessionStart;
	std::vector<BYTE> m_buffer;
	Logger m_logger;

public:
	NetworkMonitor() : hDevice(INVALID_HANDLE_VALUE), m_totalProcessed(0)
	{
		size_t buffer_size = sizeof(NETWORK_EVENT_INFO) * MAX_EVENTS_PER_POLL + sizeof(NETMON_GET_EVENTS_RESPONSE);
		m_buffer.resize(buffer_size);
	}

	~NetworkMonitor() {
		Cleanup();
	}

	bool Initialize()
	{
		if (!m_logger.Initialize())
		{
			printf("Warning: logger initiazlization failed\n");
		}

		hDevice = CreateFile(
			DEVICE_NAME,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hDevice == INVALID_HANDLE_VALUE)
		{
			printf("Error: Failed creating device, Error:%lu\n", GetLastError());
			m_logger.LogMessage("Failed opening device");
			return false;
		}

		printf("Successfully connected to the netmon device\n");
		m_logger.LogMessage("Successfully connected to the netmon device\n");
		
		return true;
	}

	void PrintBanner() {
		m_console.Set(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		printf("\n|-------------------------------------------------------------|\n");
		  printf("|            NETWORK MONITOR AGENT POC                        |\n");
		  printf("|-------------------------------------------------------------|\n");
		  m_console.Reset();
	}

	void Cleanup()
	{
		if (hDevice != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hDevice);
			hDevice = INVALID_HANDLE_VALUE;
		}

		m_logger.LogMessage("Network Monitor Agent shutting down");
		m_logger.Close();
		g_running = false;
	}

	std::string FormatEvent(const PNETWORK_EVENT_INFO pEvent)
	{
		std::stringstream ss;

		const char* eventTypeName = GetEventTypeName(pEvent->EventType);
		char localAddr[16];
		char remoteAddr[16];
		FormatIPAddress(pEvent->LocalAddress, localAddr);
		FormatIPAddress(pEvent->RemoteAddress, remoteAddr);

		char in[] = " <- ";
		char out[] = " -> ";
		char* direction = (pEvent->IsInbound ? in : out);



		switch (pEvent->EventType)
		{
		case EVENT_TYPE_PACKET_DATA:
		{
			ss << "\n[ " << eventTypeName << " ] " << GetProtocolName(pEvent->Protocol)
				<< " " << localAddr << ":" << pEvent->LocalPort << direction << remoteAddr << ":" << pEvent->RemotePort
				<< " [" << pEvent->DataLength << " Bytes ]";
			if (strlen(pEvent->ApplicationProtocol) > 0) {
				ss << " " << pEvent->ApplicationProtocol;
			}
			break;
		}
		case EVENT_TYPE_OUTBOUND_CONNECT:
		{
			ss  << "\n[ " << eventTypeName << " ] " << GetProtocolName(pEvent->Protocol)
				<< " PID:" << pEvent->ProcessId
				<< " " << localAddr << ":" << pEvent->LocalPort << direction << remoteAddr << ":" << pEvent->RemotePort
				<< " [" << pEvent->DataLength << " Bytes ]";
			if (strlen(pEvent->ApplicationProtocol) > 0) {
				ss << " " << pEvent->ApplicationProtocol;
			}
			if (wcslen(pEvent->ProcessPath) > 0) {
				ss << " [" << WideToNarrow(GetProcessName(pEvent->ProcessPath)) << "]";
			}
			break;
		}
		case EVENT_TYPE_INBOUND_ACCEPT:
		{
			ss << "\n[ " << eventTypeName << " ] " << GetProtocolName(pEvent->Protocol)
				<< " PID:" << pEvent->ProcessId
				<< " " << localAddr << ":" << pEvent->LocalPort << direction << remoteAddr << ":" << pEvent->RemotePort
				<< " [" << pEvent->DataLength << " Bytes ]";
			if (strlen(pEvent->ApplicationProtocol) > 0) {
				ss << " " << pEvent->ApplicationProtocol;
			}
			if (wcslen(pEvent->ProcessPath) > 0) {
				ss << " [" << WideToNarrow(GetProcessName(pEvent->ProcessPath)) << "]";
			}
			break;
		}
		case EVENT_TYPE_LISTEN:
		{
			ss << "\n[ " << eventTypeName << " ] " << GetProtocolName(pEvent->Protocol)
				<< " PID:" << pEvent->ProcessId
				<< " " << localAddr << ":" << pEvent->LocalPort;

			if (wcslen(pEvent->ProcessPath) > 0) {
				ss << " [" << WideToNarrow(GetProcessName(pEvent->ProcessPath)) << "]";
			}
			break;
		}
		default:
		{
			break;
		}
		}
		return ss.str();
	}

	void ProcessEvent(const PNETWORK_EVENT_INFO pEvent) {

		std::string formattedEvent = FormatEvent(pEvent);

		m_console.Set(ConsoleColor::GetEventColor(pEvent->EventType));
		printf("%s", formattedEvent.c_str());
		m_console.Reset();
		printf("\n");

		// Log to file
		m_logger.LogMessage(formattedEvent);
	}

	VOID Poll()
	{
		NETMON_GET_EVENTS_REQUEST request = { MAX_EVENTS_PER_POLL };
		DWORD bytesReturned = 0;

		if (!DeviceIoControl(
			hDevice,
			IOCTL_NETMON_GET_EVENT,
			&request,
			sizeof(NETMON_GET_EVENTS_REQUEST),
			m_buffer.data(),
			(DWORD)m_buffer.size(),
			&bytesReturned,
			NULL))
		{
			DWORD error = GetLastError();
			printf("Failed io control request %ul\n", error);
			return;
		}

		PNETMON_GET_EVENTS_RESPONSE response = (PNETMON_GET_EVENTS_RESPONSE)m_buffer.data();
		for (ULONG i = 0; i < response->EventCount; i++)
		{
			ProcessEvent(&response->Events[i]);
		}
	}

	VOID Run()
	{
		g_running = true;
		PrintBanner();
		while (g_running)
		{
			Poll();
			Sleep(POLL_INTERVAL_MS);
		}
	}
};

