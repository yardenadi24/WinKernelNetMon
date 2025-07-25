// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "Agent.h"
#include <iostream>


void Usage()
{
    printf("Usage: NetMon.exe <full log file path>\n");
}

int main(int argc, char * argv[])
{
    printf("------------- Welcome to the NetMon agent -------------\n ");   

    // Set up signal handlers
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    NetworkMonitor netMonAgent;
    netMonAgent.Initialize();

    try {
        netMonAgent.Run();
    }
    catch (const std::exception& e) {
        printf("\n[FATAL] Exception: %s\n", e.what());
        return 1;
    }

    printf("\n[INFO] Network Monitor Agent stopped.\n");
    return 0;

}
