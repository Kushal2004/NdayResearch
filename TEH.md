# Process Injection: Thread Execution Hijacking

## Process Injection

Process Injection is a technique used by attackers to inject malicious code into the address space of another process. This allows them to prevent detection and elevate privileges.

One of the sub-techniques of process injection is Thread Execution Hijacking, also known as Suspend, Inject, and Resume (SIR). This technique is used by malware to inject code into an existing thread of a running process. This method avoids the creation of new processes or threads, which can be noisy and more easily detected by security measures.

## Mechanism of Thread Execution Hijacking

### Identifying the Target Process

The attacker identifies a running process to hijack. The attacker usually chooses a process that has higher privileges or access to sensitive information/resources. The malware uses functions like `CreateToolhelp32Snapshot()` , `Thread32First()`, `Thread32Next()` to enumerate through the existing threads of a target process. These API calls help in identifying the thread that will be hijacked.

***Snapshot: A collection of system objects captured at a point in time***

CreateTOolhelp32Snapshort() inclues lot of parameters such as 
- TH32CS_SNAPHEAPLIST: Includes the heap list of the process specified in th32ProcessID.
- TH32CS_SNAPPROCESS: Includes all processes in the system.
- TH32CS_SNAPTHREAD: Includes all threads in the system.
- TH32CS_SNAPMODULE: Includes all modules of the process specified in th32ProcessID.
- TH32CS_SNAPMODULE32: Includes all 32-bit modules of the process specified in th32ProcessID when running on a 64-bit system.
- TH32CS_SNAPALL: Includes all of the above.

```cpp
THREADENTRY32 threadEntry;

HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specificed process
	TH32CS_SNAPTHREAD, // Include all processes residing on the system
	0 // Indicates the current process
);
Thread32First( // Obtains the first thread in the snapshot
	hSnapshot, // Handle of the snapshot
	&threadEntry // Pointer to the THREADENTRY32 structure
);

while (Thread32Next( // Obtains the next thread in the snapshot
	snapshot, // Handle of the snapshot
	&threadEntry // Pointer to the THREADENTRY32 structure
)) 

```
### Gaining a Handle to the Process

Using Windows API calls such as `OpenProcess` and `OpenThread`, the attacker obtains handles to the target process and its threads. These handles allow them to manipulate the process's execution.

```cpp
//Open a Handle to the Target Process:
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,targetProcessId);

//Open a Handle to a Thread in the Target Process:
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);

```

### Suspending the Target Thread

The identified thread within the process is suspended using the `SuspendThread` API call. Suspending the thread ensures that it is not executing any instructions while it is being manipulated. This ensures that the thread's execution is paused, allowing the malware to safely inject its code without interference.

```cpp
SuspendThread(hThread);

```

### Allocating Memory in the Target Process

Memory within the address space of the target process is allocated for the malicious code. This is typically done using `VirtualAllocEx`, which reserves a region of memory that can be written to and executed from.

```cpp
LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

```

### Writing Malicious Code

The attacker then writes the malicious code or a DLL path into the allocated memory using `WriteProcessMemory`. This step plants the payload that will be executed within the context of the hijacked process. The malware writes its payload into the allocated memory using `WriteProcessMemory`. The payload could be shellcode, a path to a malicious DLL, or the address of `LoadLibrary`.

```cpp
WriteProcessMemory(hProcess, pRemoteCode, payload, payloadSize, NULL);

```

### Modifying the Thread Context

The context of the suspended thread (which includes the thread's register states and execution pointers) is retrieved using `GetThreadContext` to be modified to point to the injected code. This is achieved using `SetThreadContext`, which changes the thread's instruction pointer to the address of the malicious code.

```cpp
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)pRemoteCode;
SetThreadContext(hThread, &ctx);

```
### Resuming the Thread

Finally, the thread is resumed using the `ResumeThread` API call. As the thread resumes execution, it starts running the injected malicious code.

```cpp
ResumeThread(hThread);

```

## Advantages of Thread Execution Hijacking

### Evasion of Security Measures

By running malicious code in the context of a legitimate process, attackers can evade many security mechanisms that rely on process-based detection.

### Access to Resources

The malicious code gains access to the memory, system, and network resources of the hijacked process. This can include sensitive data and privileged operations.

### Privilege Escalation

If the hijacked process has elevated privileges, the malicious code can inherit these privileges, allowing the attacker to perform actions that would normally require higher levels of access.

---
Thread Context
Understanding thread context is crucial for hijacking. Every thread has a scheduling priority and a set of structures saved to its context, including CPU registers and the stack. The WinAPIs GetThreadContext and SetThreadContext are used to retrieve and set a thread's context, respectively.

Modifying The Thread's Context: Retrieve the thread's context using GetThreadContext, modify the instruction pointer register to point to the payload, and set the context back using SetThreadContext.

8. Setting ContextFlags
Before calling GetThreadContext, the CONTEXT.ContextFlags must be set to CONTEXT_CONTROL or CONTEXT_ALL. This step ensures that the necessary parts of the context are retrieved and can be modified for hijacking.

Thread Identification: Each process in Windows runs one or more threads, where each thread is responsible for executing a specific set of instructions. When you aim to hijack a process, you first need to identify which thread within that process you want to take control of.

Thread Enumeration (Thread32First() and Thread32Next()):

It then iterates through each thread in the snapshot using Thread32First() and Thread32Next() functions. For each thread, it retrieves information using a THREADENTRY32 structure (threadEntry).
Thread Identification:

Within the loop, it checks if the th32OwnerProcessID of the current threadEntry matches the processId provided to the InjectAndHijackThread() function. This comparison ensures that the thread belongs to the target process you are interested in.
123