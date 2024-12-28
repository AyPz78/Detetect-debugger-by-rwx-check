#include <windows.h>
#include <stdio.h>
#include <string>
#include <set>
#include <algorithm>
#include <TlHelp32.h>
#include <process.h>
#include <vector>
#include <Psapi.h>
#include <winternl.h>
#include <iostream>

void print_in_red(const char* message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("%s", message);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Reset couleur
}

void detect_debugger() {
    if (IsDebuggerPresent()) {
        print_in_red("Debugger detected!\n");
    }
    else {
        printf("Debugger not detected.\n");
    }
}


void detect_rwx_segments() {
	MEMORY_BASIC_INFORMATION mbi;//use this class to get more information to avoid fake positives
    unsigned char* address = nullptr;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) //I will advise you to add some check ^^
        {
           print_in_red("RWX segment detected!\n");
        }
        address += mbi.RegionSize;
    }
}

void detect_debugger_bypeb() {

	if (auto peb = reinterpret_cast<PEB*>(reinterpret_cast<TEB*> (__readgsqword(0x30))->ProcessEnvironmentBlock)->BeingDebugged)
	{
		print_in_red("Debugger detected via PEB!\n");
		Sleep(10000);
	}
	else
	{
		printf("Debugger not detected via PEB.\n");
	}
}

void init() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);

	
    while (true) {
        Sleep(1000);
       // detect_debugger();
        detect_debugger_bypeb();//just example
		detect_rwx_segments();//better way to detect debugger

    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)init, 0, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

