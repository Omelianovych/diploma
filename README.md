# eBPF HIDS

A lightweight **Host-based Intrusion Detection System (HIDS) for Linux** built with eBPF.

The system monitors security-relevant Linux system calls in real time, enriches the collected events in user space, and analyzes them using configurable detection rules. Detected activity can be mapped to relevant **MITRE ATT&CK** techniques.

## Architecture

* **eBPF / C** — kernel-level collection and filtering of system call events
* **Go** — event processing, enrichment, analysis, and rule engine
* **Ring Buffer** — communication between kernel and user space
* **YAML rules** — configurable threat detection logic
* **MITRE ATT&CK** — threat classification

## Monitored Activity

The prototype focuses on security-relevant operations such as:

* process execution (`execve`)
* file access (`openat`)
* network connections (`connect`, `accept`)
* process tracing (`ptrace`)
* in-memory execution (`memfd_create`)
* permission changes (`chmod`)

The project was developed as part of a master's thesis on **Linux security monitoring based on system call analysis**.
