# Process Injection: Thread Execution Hijacking

## Process Injection

Process Injection is a technique used by attackers to inject malicious code into the address space of another process. This allows them to prevent detection and elevate privileges.

One of the sub-techniques of process injection is Thread Execution Hijacking, also known as Suspend, Inject, and Resume (SIR). This technique is used by malware to inject code into an existing thread of a running process. This method avoids the creation of new processes or threads, which can be noisy and more easily detected by security measures.

## Mechanism of Thread Execution Hijacking

### Identifying the Target Process

The attacker identifies a running process to hijack. The attacker usually chooses a process that has higher privileges or access to sensitive information/resources. The malware uses functions like `CreateToolhelp32Snapshot` and `Thread32First` to enumerate through the existing threads of a target process. These API calls help in identifying the thread that will be hijacked.

### Gaining a Handle to the Process

Using Windows API calls such as `OpenProcess` and `OpenThread`, the attacker obtains handles to the target process and its threads. These handles allow them to manipulate the process's execution.

### Suspending the Target Thread

The identified thread within the process is suspended using the `SuspendThread` API call. Suspending the thread ensures that it is not executing any instructions while it is being manipulated. This ensures that the thread's execution is paused, allowing the malware to safely inject its code without interference.

### Allocating Memory in the Target Process

Memory within the address space of the target process is allocated for the malicious code. This is typically done using `VirtualAllocEx`, which reserves a region of memory that can be written to and executed from.

### Writing Malicious Code

The attacker then writes the malicious code or a DLL path into the allocated memory using `WriteProcessMemory`. This step plants the payload that will be executed within the context of the hijacked process. The malware writes its payload into the allocated memory using `WriteProcessMemory`. The payload could be shellcode, a path to a malicious DLL, or the address of `LoadLibrary`.

### Modifying the Thread Context

The context of the suspended thread (which includes the thread's register states and execution pointers) is retrieved using `GetThreadContext` to be modified to point to the injected code. This is achieved using `SetThreadContext`, which changes the thread's instruction pointer to the address of the malicious code.

### Resuming the Thread

Finally, the thread is resumed using the `ResumeThread` API call. As the thread resumes execution, it starts running the injected malicious code.

## Advantages of Thread Execution Hijacking

### Evasion of Security Measures

By running malicious code in the context of a legitimate process, attackers can evade many security mechanisms that rely on process-based detection.

### Access to Resources

The malicious code gains access to the memory, system, and network resources of the hijacked process. This can include sensitive data and privileged operations.

### Privilege Escalation

If the hijacked process has elevated privileges, the malicious code can inherit these privileges, allowing the attacker to perform actions that would normally require higher levels of access.
