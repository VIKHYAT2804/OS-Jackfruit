# Multi-Container Runtime — OS-Jackfruit

## 1. Team Information

| Name | SRN |
|------|-----|
| Vikhyat Agrawal | PES2UG24CS585 |
| Vineet Toshniwal | PES2UG24CS589 |

---

## 2. Build, Load, and Run Instructions

### Prerequisites

Ubuntu 22.04 or 24.04 VM with Secure Boot OFF. No WSL.

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### Prepare the Root Filesystem

```bash
mkdir -p rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs
```

### Build Everything

```bash
cd boilerplate
make
```

This builds: `engine`, `memory_hog`, `cpu_hog`, `io_pulse`, and `monitor.ko`.

### Copy Workload Binaries into rootfs

The Alpine rootfs does not have the host's dynamic libraries, so binaries must be statically linked:

```bash
cd boilerplate
gcc -O2 -static -o memory_hog memory_hog.c
gcc -O2 -static -o cpu_hog cpu_hog.c
gcc -O2 -static -o io_pulse io_pulse.c
cp memory_hog cpu_hog io_pulse ../rootfs/
```

### Load the Kernel Module

```bash
cd boilerplate
sudo insmod monitor.ko
ls /dev/container_monitor   # should exist
```

### Start the Supervisor

In Terminal 1:

```bash
cd ~/OS-Jackfruit
sudo ./boilerplate/engine supervisor ./rootfs
```

The supervisor blocks here, listening for CLI commands over a UNIX domain socket at `/tmp/mini_runtime.sock`.

### Use the CLI (Terminal 2)

```bash
# Start containers in background
sudo ./boilerplate/engine start alpha ./rootfs "/cpu_hog 30"
sudo ./boilerplate/engine start beta ./rootfs "/cpu_hog 30"

# List containers and metadata
sudo ./boilerplate/engine ps

# View container logs
sudo ./boilerplate/engine logs alpha

# Stop a container
sudo ./boilerplate/engine stop alpha

# Start with memory limits
sudo ./boilerplate/engine start memtest ./rootfs /memory_hog --soft-mib 5 --hard-mib 10

# Start with scheduling priority
sudo ./boilerplate/engine start highpri ./rootfs "/cpu_hog 20" --nice -5
sudo ./boilerplate/engine start lowpri ./rootfs "/cpu_hog 20" --nice 10
```

### Inspect Kernel Logs

```bash
sudo dmesg | grep container_monitor | tail -20
```

### Shutdown and Cleanup

Press Ctrl+C in Terminal 1 to stop the supervisor. Then:

```bash
sudo rmmod monitor
ps aux | grep engine   # should show nothing
```

---

## 3. Demo with Screenshots

### Screenshot 1 — Multi-container supervision

Two containers (`alpha` and `beta`) started under a single supervisor process.

<img src="https://github.com/user-attachments/assets/ee5241a8-c589-48dc-b1f4-032f2a0016f5" width="100%">


### Screenshot 2 — Metadata tracking

Output of `engine ps` showing all tracked containers.

<img src="https://github.com/user-attachments/assets/75dc2b31-c91c-4508-aae8-dc57ee0aa6dd" width="100%">


### Screenshot 3 — Bounded-buffer logging

Contents of `logs/alpha.log`.

<img src="https://github.com/user-attachments/assets/715a73ac-c681-4e42-b452-e771a7e1d803" width="100%">


### Screenshot 4 — CLI and IPC

Stop command communication with supervisor.

<img src="https://github.com/user-attachments/assets/543f9ab4-00ac-44b9-9d74-873667f95b91" width="100%">


### Screenshot 5 — Soft-limit warning

Kernel detects memory soft limit.

<img src="https://github.com/user-attachments/assets/33862cfa-3865-4ff2-84a6-97e36ad665a1" width="100%">


### Screenshot 6 — Hard-limit enforcement

Kernel kills container on hard limit breach.

<img src="https://github.com/user-attachments/assets/4520e66e-e04d-4a6d-8939-7dc79a85b5a5" width="100%">


### Screenshot 7 — Scheduling experiment

High vs low priority containers.

<img src="https://github.com/user-attachments/assets/df1a24fb-b693-4765-8f49-ce77492bfd81" width="100%">


### Screenshot 8 — Clean teardown

No zombie processes after shutdown.

<img src="https://github.com/user-attachments/assets/c6c37d01-117a-4d3b-8ac7-b0fa9475b0be" width="100%">
## 4. Engineering Analysis

### 4.1 Isolation Mechanisms

The runtime achieves process and filesystem isolation using Linux namespaces and `chroot`. Each container is created with `clone()` using three namespace flags: `CLONE_NEWPID` gives the container its own PID namespace so its first process appears as PID 1 inside but has a real host PID outside; `CLONE_NEWUTS` gives it an independent hostname (set to the container ID); and `CLONE_NEWNS` gives it a private mount namespace so `proc` can be mounted inside without affecting the host.

After `clone()`, the child calls `chroot()` to the container's rootfs directory, making the Alpine filesystem the root. This prevents the container from accessing host filesystem paths. `/proc` is mounted explicitly inside the container so process information works correctly.

The host kernel is still fully shared — there is no separate kernel per container. The host kernel's scheduler, memory manager, device drivers, and system call interface are all shared. Namespaces only virtualize the view of certain resources; they do not create kernel-level isolation like a full VM does.

### 4.2 Supervisor and Process Lifecycle

A long-running parent supervisor is useful because it maintains persistent state across multiple container lifetimes. Without it, each CLI invocation would be stateless and could not track metadata, manage logs, or coordinate cleanup.

The supervisor uses `clone()` instead of `fork()+exec()` to create containers, giving fine-grained control over which namespaces are shared. The parent-child relationship means the supervisor must reap exited children — failing to do so leaves zombie processes that consume PID table entries. `SIGCHLD` is handled with `SA_NOCLDSTOP` and `waitpid(-1, &status, WNOHANG)` in a loop to reap all children without blocking. The metadata record for each container is updated atomically under `metadata_lock` when a child exits, tracking whether it exited normally or was killed by a signal.

### 4.3 IPC, Threads, and Synchronization

The project uses two IPC mechanisms. The first is pipes — each container's stdout and stderr are connected to the supervisor via a pipe created before `clone()`. The write end is inherited by the child and the read end stays in the supervisor. A dedicated log reader thread per container reads from this pipe and pushes chunks into the bounded buffer.

The second IPC mechanism is a UNIX domain socket at `/tmp/mini_runtime.sock`. CLI client processes connect, send a `control_request_t` struct, and read back a `control_response_t`. This separates the control path from the logging path entirely.

The bounded buffer uses a `pthread_mutex_t` to protect the head, tail, and count fields, and two `pthread_cond_t` variables (`not_full` and `not_empty`) to block producers when the buffer is full and consumers when it is empty. Without the mutex, concurrent reads and writes to the buffer fields would produce torn values — for example a producer could read `count`, get preempted, and a consumer could decrement it before the producer increments, resulting in a count that is permanently off by one. Without condition variables, threads would spin-poll, wasting CPU.

The container metadata list uses a separate `metadata_lock` mutex. This is kept separate from the buffer lock to avoid holding two locks simultaneously, which would risk deadlock.

### 4.4 Memory Management and Enforcement

RSS (Resident Set Size) measures the number of physical memory pages currently mapped into a process's address space. It does not measure virtual memory that has been allocated but not yet touched (due to Linux's lazy allocation), memory-mapped files that are shared with other processes, or swap usage.

Soft and hard limits are different policies by design. A soft limit is a warning threshold — the process is still allowed to run but an operator is notified that memory usage is elevated. This is useful for observability without disrupting the workload. A hard limit triggers termination — once the process exceeds this threshold the kernel module sends `SIGKILL`.

Enforcement belongs in kernel space rather than only in user space for two reasons. First, a user-space monitor cannot reliably kill a process that is consuming memory faster than the polling interval — between two polls the process could allocate gigabytes. Second, a malicious or buggy container process could interfere with a user-space monitor (e.g., by sending it signals), whereas a kernel module runs with full privilege and cannot be blocked by the monitored process.

### 4.5 Scheduling Behavior

The scheduler experiment ran two `cpu_hog` containers simultaneously for 20 seconds. `highpri` was started with `nice -5` and `lowpri` with `nice 10`. Both completed in exactly 20 seconds of wall-clock time because the workload duration is measured in wall-clock time inside `cpu_hog`, not CPU time.

The Linux CFS scheduler translates nice values into weights. A process with `nice -5` gets a higher weight and therefore a larger share of CPU time per scheduling period compared to one with `nice 10`. On a single CPU VM this means `highpri` gets more CPU quanta per second and its accumulator advances faster per wall-clock second, while `lowpri` gets fewer quanta and is preempted more often. The difference is visible in the accumulator values and in the fact that `highpri` reports elapsed seconds more consistently without gaps.

This demonstrates CFS's fairness goal: CPU time is proportional to priority weight, not equal shares, so high-priority work makes faster progress while lower-priority work still makes forward progress rather than starving entirely.

---

## 5. Design Decisions and Tradeoffs

### Namespace Isolation

**Choice:** PID + UTS + mount namespaces via `clone()`, with `chroot()` for filesystem isolation.

**Tradeoff:** Using `chroot()` instead of `pivot_root()` is simpler but less secure — a privileged process inside the container could potentially escape the chroot. `pivot_root()` would be more robust but requires more filesystem setup.

**Justification:** For this project's scope, `chroot()` provides sufficient isolation to demonstrate the concept while keeping the implementation straightforward.

### Supervisor Architecture

**Choice:** Single long-running supervisor process with a UNIX domain socket control channel.

**Tradeoff:** The supervisor is a single point of failure — if it crashes, all container metadata is lost. A more robust design would persist metadata to disk.

**Justification:** In-memory metadata is sufficient for a demonstration runtime. Persistence would add significant complexity without contributing to the OS concepts being demonstrated.

### IPC and Logging

**Choice:** Pipes for log data, UNIX domain socket for control commands, bounded buffer with mutex + condition variables.

**Tradeoff:** Opening and closing the log file on every buffer pop is inefficient for high-throughput logging. A better approach would keep the file descriptor open per container. However, this would require tracking open file descriptors alongside the metadata.

**Justification:** The current design keeps the logging thread simple and avoids file descriptor leaks on container exit, which is more important for correctness in a short-lived demo.

### Kernel Monitor

**Choice:** Timer-based periodic RSS polling at 1-second intervals using `find_pid_ns` with `init_pid_ns` to look up host PIDs.

**Tradeoff:** A 1-second polling interval means a container could exceed the hard limit by a large margin before being killed if it allocates memory very rapidly. Event-driven enforcement (e.g., using cgroups memory pressure notifications) would be more accurate but far more complex to implement as an LKM.

**Justification:** Periodic polling is sufficient to demonstrate the soft/hard limit concept and is much simpler to implement correctly in kernel space than an event-driven approach.

### Scheduling Experiments

**Choice:** `nice` values to differentiate container priorities, measured via wall-clock elapsed time and accumulator progress in `cpu_hog`.

**Tradeoff:** `nice` values affect CFS weight but the effect is most visible under CPU contention. On a lightly loaded system the difference may be small. CPU affinity pinning would produce more dramatic and repeatable results.

**Justification:** `nice` values are the simplest way to demonstrate scheduler priority influence without requiring cgroup CPU controllers or real-time scheduling policies.

---

## 6. Scheduler Experiment Results

### Setup

Two containers ran concurrently on a single-CPU VM:

| Container | Command | Nice value |
|-----------|---------|------------|
| highpri | `/cpu_hog 20` | -5 (higher priority) |
| lowpri | `/cpu_hog 20` | +10 (lower priority) |

### Results

Both containers completed in 20 seconds of wall-clock time. The `highpri` container reported elapsed seconds consistently with no gaps, while the `lowpri` container showed occasional delays between elapsed-second reports, indicating it was being preempted more frequently by the scheduler to give CPU time to `highpri`.

The final accumulator values differed between runs, reflecting the different amounts of CPU time each container actually received per wall-clock second.

### Analysis

Linux CFS (Completely Fair Scheduler) does not use static time slices. Instead it assigns each process a virtual runtime and always schedules the process with the lowest virtual runtime. Nice values map to weight multipliers: `nice -5` gives approximately 1.5× the weight of `nice 0`, while `nice 10` gives approximately 0.5× the weight. Under CPU contention, `highpri` therefore receives roughly 3× more CPU time per wall-clock second than `lowpri`.

This confirms CFS's design goal: CPU allocation is proportional to weight (priority), ensuring high-priority work makes faster progress while low-priority work still makes forward progress rather than starving. The experiment demonstrates that even a simple nice-value difference measurably affects scheduling behaviour in a multi-container workload.
