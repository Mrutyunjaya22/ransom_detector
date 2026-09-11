# Kernel Telemetry & In-Line Prevention Architecture Specification
**Enterprise EDR Ransomware Detection & SOC Triage Platform**

---

## 1. Executive Summary & Kernel Mission
User-space telemetry mechanisms (e.g., `watchdog`, `ReadDirectoryChangesW`, `psutil`) operate asynchronously after operations have already completed on disk. When confronting advanced ransomware families (such as LockBit 3.0, BlackCat/ALPHV, or Royal), encryption throughput can exceed **20,000 files per minute**. 

To guarantee **zero-loss file protection**, detection and mitigation must shift into the OS kernel to enforce **in-line blocking** before file writes or file renames are committed to the underlying filesystem.

This document details the architectural blueprints for:
1. **Windows Minifilter Driver** (`fltmgr.sys` / `edr_filter.sys`)
2. **Linux eBPF Subsystem** (`bpf_lsm` / `tracepoint` ring buffers)
3. **High-Performance Kernel-to-User Space Inter-Process Communication (IPC)**
4. **Anti-BSOD & Kernel Stability Safeguards**

---

## 2. Windows Minifilter Driver Architecture (`edr_filter.sys`)

### 2.1 Driver Registration & Filter Manager Model
The Windows kernel component is built as a File System Minifilter Driver managed by the Windows Filter Manager (`fltmgr.sys`). Minifilter drivers register pre-operation and post-operation callbacks at a designated altitude.

- **Recommended Altitude:** `320000 - 329999` (FSFilter Anti-Virus / EDR)
- **Primary Filter Entrypoint:** `DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)`

```c
#include <fltKernel.h>

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      EdrPreCreateCallback,
      EdrPostCreateCallback },

    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      EdrPreWriteCallback,
      EdrPostWriteCallback },

    { IRP_MJ_SET_INFORMATION,
      0,
      EdrPreSetInformationCallback,
      EdrPostSetInformationCallback },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    EdrFilterUnload,
    EdrInstanceSetup,
    EdrInstanceQueryTeardown,
    EdrInstanceTeardownStart,
    EdrInstanceTeardownComplete,
    NULL, NULL, NULL
};
```

### 2.2 In-Line Pre-Operation Blocking (`IRP_MJ_SET_INFORMATION` & `IRP_MJ_WRITE`)
When a process issues file renames (e.g. appending `.locked` extensions) or mass encrypted block writes:

1. **Pre-Rename Interception (`IRP_MJ_SET_INFORMATION`):**
   - The driver inspects `FileRenameInformation` / `FileRenameInformationEx`.
   - If the destination extension matches known ransomware indicators or Canary file signatures, the driver instantly aborts the I/O in kernel space:
   ```c
   FLT_PREOP_CALLBACK_STATUS EdrPreSetInformationCallback(
       PFLT_CALLBACK_DATA Data,
       PCFLT_RELATED_OBJECTS FltObjects,
       PVOID *CompletionContext
   ) {
       if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
           PFILE_RENAME_INFORMATION renameInfo = 
               (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
           
           if (IsSuspiciousExtension(renameInfo->FileName, renameInfo->FileNameLength)) {
               // Reject I/O immediately before disk mutation
               Data->IoStatus.Status = STATUS_ACCESS_DENIED;
               Data->IoStatus.Information = 0;
               NotifyUserSpaceSensor(PsGetCurrentProcessId(), renameInfo->FileName, EVENT_SUSPICIOUS_RENAME);
               return FLT_PREOP_COMPLETE;
           }
       }
       return FLT_PREOP_SUCCESS_NO_CALLBACK;
   }
   ```

2. **In-Kernel Shannon Entropy Sliding Window:**
   - For write operations (`IRP_MJ_WRITE`), the driver calculates byte distribution histograms on write buffers. If high entropy ($\ge 7.6$) is detected in previously plaintext files, the process is placed in a temporary kernel suspend state while the behavioral engine evaluates risk.

---

## 3. Linux eBPF Subsystem Architecture

On Linux kernels (5.7+), the EDR agent attaches eBPF programs via **LSM (Linux Security Module)** and **tracepoint** hooks to monitor and enforce disk integrity without compiling custom kernel modules.

### 3.1 Hook Points & Functions
- `lsm/path_rename`: Enforces inline access control when a process attempts mass file renames.
- `lsm/file_open`: Prevents access to shadow backups or system restore points.
- `tracepoint/syscalls/sys_enter_write`: Records high-frequency I/O write bursts and streams metadata over `BPF_MAP_TYPE_RINGBUF`.

### 3.2 eBPF Program Implementation (C Skeleton)
```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16MB ring buffer
} telemetry_ringbuf SEC(".maps");

struct telemetry_event_t {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char old_path[256];
    char new_path[256];
    __u64 timestamp_ns;
};

SEC("lsm/path_rename")
int BPF_PROG(edr_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if new_dentry ends in known ransomware patterns
    if (dentry_has_suspicious_extension(new_dentry)) {
        // Enforce immediate block in Linux kernel
        return -EPERM; // Operation not permitted
    }
    
    // Stream event to user-space agent ring buffer
    struct telemetry_event_t *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->timestamp_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 4. Kernel-to-User Space Inter-Process Communication (IPC)

### 4.1 Filter Communication Ports (Windows)
- Uses `FltCreateCommunicationPort` in the driver.
- The user-space EDR agent (`agent/edr_agent.py` or compiled C++ service) connects using `FilterConnectCommunicationPort`.
- Bidirectional asynchronous messaging:
  - **Kernel to User:** `FltSendMessage` alerts the agent of suspicious file write bursts.
  - **User to Kernel:** `FilterReplyMessage` instructs the driver to release the operation or immediately revoke file-handle permissions (`STATUS_ACCESS_DENIED`) and issue `ZwTerminateProcess`.

### 4.2 Linux eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`)
- Single memory-mapped page buffer between kernel and user space.
- Sub-microsecond latency, zero memory copies, and lock-free thread synchronization.

---

## 5. Anti-BSOD & High-Availability Safeguards

1. **Deadlock Prevention:**
   - Kernel callbacks must never issue synchronous network requests or block on user-space RPC calls.
   - All external scoring queries are bounded by a strict kernel timer (e.g., 50ms). If user-space does not reply within 50ms, the filter defaults to `FLT_PREOP_SUCCESS` (fail-open for benign system files) or terminates suspicious processes.

2. **Paging I/O Exemption:**
   - Memory mapped writes with `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO` must be skipped during pre-write to prevent recursive filesystem deadlocks.

3. **Safe Unload & Diagnostic Crash Dump:**
   - The driver supports non-forced dynamic unloading via `FltUnregisterFilter`.
   - All memory allocations utilize tagged non-paged pool memory (`ExAllocatePoolWithTag(NonPagedPoolNx, size, 'EDRM')`).
