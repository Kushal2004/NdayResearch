# Procedure Examples of Thread Execution Hijacking

Thread Execution Hijacking is employed by various malware families to inject malicious code into running processes, evading detection and gaining elevated privileges. Here are detailed examples of malware that use this technique:

## S0168: Gazer

**Description**: Gazer is an advanced persistent threat (APT) malware that targets government and diplomatic organizations. It is known for its sophisticated techniques to evade detection and persist in infected systems.
This was used as a backdoor by Turla , Trula is a cyber threat group that has been attributed to Russia's Federal Security Service (FSB). They have compromised victims in over 50 countries since at least 2004, spanning a range of industries including government, embassies, military, education, research and pharmaceutical companies
Southeastern Europe as well as countries in the former Soviet Union Republichas recently been the main target

**Thread Execution Hijacking in Gazer**:

- **Objective**: Gazer uses thread execution hijacking to inject its orchestrator module into a running thread of a remote process.
- **Language** : Written in C++
- **Process**:
  1. **Initial Compromise**: Gazer first compromises a target system through phishing or exploiting vulnerabilities.
  2. **Process Enumeration**: It identifies a suitable target process, typically one that is commonly running and has high privileges, such as `svchost.exe`.
  
- **References**: [eset-gazer](https://web-assets.esetstatic.com/wls/2017/08/eset-gazer.pdf)

## S0094: Trojan.Karagany

**Description**: Trojan.Karagany is a malware that has been used for espionage and data theft. It is known for its modular architecture and ability to inject itself into other processes.

Trojan.Karagany is linked to Dragonfly which is a cyber espionage group that has been attributed to Russia's Federal Security Service (FSB)

**Thread Execution Hijacking in Trojan.Karagany**:

- **Objective**: Karagany injects a suspended thread from its own process into a new target process, which is then executed.
- **Process**:
  1. **Initial Execution**: Karagany runs initially within the context of a compromised process.
  2. **Thread Creation and Suspension**: It creates a thread within its own process and immediately suspends it using `CreateThread` and `SuspendThread`.
  3. **Target Process Identification**: It identifies a new target process to inject into, often selecting one with higher privileges.
  4. **Memory Allocation in Target**: Karagany allocates memory within the target process using `VirtualAllocEx`.
  5. **Code Injection**: It writes the suspended thread's code into the allocated memory of the target process using `WriteProcessMemory`.
  6. **Context Transfer**: The context of the suspended thread is modified to point to the injected code in the target process using `SetThreadContext`.
  7. **Thread Resumption**: The suspended thread is then resumed within the target process using `ResumeThread`.
  
- **Outcome**: This allows Karagany to execute its payload within the context of the new process, making it harder to detect and terminate.
- **References**: [BroadCom NewsLetter](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=7382dce7-0260-4782-84cc-890971ed3f17&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments)

## S0579: Waterbear

**Description**: Waterbear is a modular malware platform known for targeting East Asian entities. It is notable for its ability to inject code into security software processes.

Waterbear is linked to the BlackTech Group, a cybercrime group that has been attributed to Chaina.

