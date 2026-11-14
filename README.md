# Network Recon Lab: Nmap and a minimal Python scanner

Service discovery and vulnerability checks with Nmap against lab hosts, focusing on FTP, SSH, Telnet and SMB, plus a small Python TCP connect scanner that shows what a port scan does at the socket level.

> **Status:** lab notes from January 2025, cleaned up and merged in November 2026. The Python scanner used to be a separate repo (`custom-port-scanner`) that described code it didn't contain. The code is now here, in [`scanner/`](scanner/tcp_connect_scan.py). Scan only hosts you own or have written permission to test.

## Nmap
### Scope
Set targets once and reuse them:
```bash
export TARGETS="192.168.56.0/24"     # lab host-only network
```

### 1. Service discovery
```bash
nmap -sV -p 21,22,23,445 -T4 $TARGETS
```
- `-sV` probes open ports for the service name and version.
- `-T4` uses faster timing. Fine on a lab network; on a production network use `-T3` or lower so you don't trip IDS rules or overload fragile devices.

### 2. Vulnerability scripts
```bash
nmap --script vuln -p 21,22,23,445 $TARGETS
nmap --script smb-vuln* -p 445 $TARGETS
```
NSE `vuln` scripts flag known issues from version strings and safe checks. Treat their output as leads to confirm, not as proof.

### 3. Full profile of one host
```bash
nmap -A -T4 192.168.56.101
```
`-A` adds OS detection, default scripts and traceroute. It's the loudest option here, so use it on single hosts, not whole ranges.

## Lab findings
These came from intentionally vulnerable lab VMs, not production systems. The severity column is my rating.

| Service | Severity | Finding | Fix |
|---|---|---|---|
| FTP (21) | High | Anonymous login allowed, outdated server version | Disable anonymous access; replace FTP with SFTP |
| SSH (22) | Medium | Weak ciphers and key exchange offered | Update OpenSSH; restrict `Ciphers`, `KexAlgorithms` and `MACs` |
| Telnet (23) | High | Clear-text logins | Disable Telnet; use SSH |
| SMB (445) | Medium | SMBv1 enabled | Disable SMBv1. On Windows, SMBv1 without the MS17-010 patch is the EternalBlue path |

An open port is not a vulnerability by itself. The risk comes from what listens on it, its version and its configuration, which is what the `-sV` and NSE steps establish.

## Python TCP connect scanner
[`scanner/tcp_connect_scan.py`](scanner/tcp_connect_scan.py): standard library only, about 80 lines.
```bash
python3 scanner/tcp_connect_scan.py 192.168.56.101 -p 1-1024
python3 scanner/tcp_connect_scan.py 192.168.56.101 -p 21,22,23,445 --timeout 0.5
```
```
Scanning 192.168.56.101 (192.168.56.101), 1024 TCP ports
21/tcp open  ftp
22/tcp open  ssh
...
```
How it works:
- Each port gets a full TCP handshake (`connect_ex`), the same as Nmap's `-sT`. A completed handshake means open; a refusal or timeout means closed or filtered.
- A thread pool (100 workers by default) runs the connections in parallel.
- It is deliberately less capable than Nmap: no SYN scan (that needs raw sockets and root), no version detection, no UDP. It shows the mechanism, it doesn't replace the tool.

## How scans look from the other side
- **Connect scans are the easiest to see.** Every open port is a completed connection the target can log, unlike Nmap's default SYN scan, which never finishes the handshake.
- **What catches them:** IDS rules for one source touching many ports in a short window (see the [Snort lab](https://github.com/Hawkode/Snort-Lab)), firewall drop logs (Windows `pfirewall.log`, Security EID 5157), and connection logs in the SIEM.
- **Reducing exposure:** close what isn't needed, restrict management ports (SSH, SMB, RDP) to admin networks, and scan your own ranges regularly so you find changes before someone else does.
