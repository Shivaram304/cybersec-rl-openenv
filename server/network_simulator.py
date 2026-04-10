"""
NetPwn: Network Penetration Testing RL Environment
Network simulator — pure Python, no external dependencies.
"""
import random
from typing import Dict, List, Optional, Tuple, Any

VULNS: Dict[str, Dict[str, Any]] = {
    "apache_2.4.49": {"cve": "CVE-2021-41773", "technique": "cve_2021_41773", "rate": 0.85, "noise": 0.25, "grant": "user"},
    "vsftpd_2.3.4":  {"cve": "CVE-2011-2523",  "technique": "ftp_backdoor",   "rate": 0.95, "noise": 0.15, "grant": "root"},
    "samba_3.5.0":   {"cve": "CVE-2017-7494",  "technique": "eternal_blue",   "rate": 0.80, "noise": 0.55, "grant": "root"},
    "mysql_5.7":     {"cve": "CVE-2016-6662",  "technique": "sql_injection",  "rate": 0.70, "noise": 0.40, "grant": "root"},
    "openssh_7.4":   {"cve": "CVE-2018-15473", "technique": "ssh_enum",       "rate": 0.90, "noise": 0.10, "grant": "enum"},
}

NETWORK_TEMPLATE = [
    ("192.168.1.1", "Ubuntu 20.04",       {80:  {"n":"Apache",  "v":"2.4.49","vk":"apache_2.4.49"}, 22: {"n":"OpenSSH","v":"7.4","vk":"openssh_7.4"}}, "FLAG{apache_CVE-2021-41773}", False),
    ("192.168.1.2", "Windows Server 2008",{445: {"n":"Samba",   "v":"3.5.0","vk":"samba_3.5.0"},   3389:{"n":"RDP",    "v":"6.1","vk":None}},           "FLAG{sambacry_CVE-2017-7494}",True),
    ("192.168.1.3", "CentOS 7",           {21:  {"n":"vsftpd",  "v":"2.3.4","vk":"vsftpd_2.3.4"},  3306:{"n":"MySQL",  "v":"5.7","vk":"mysql_5.7"}},    "FLAG{vsftpd_CVE-2011-2523}",  False),
    ("192.168.1.4", "Debian 10",          {8080:{"n":"Tomcat",  "v":"9.0",  "vk":None},             22:  {"n":"OpenSSH","v":"8.2","vk":None}},           "",                            False),
    ("192.168.1.5", "Windows Server 2019",{80:  {"n":"IIS",     "v":"10.0", "vk":None},             443: {"n":"IIS-SSL","v":"10.0","vk":None}},          "",                            False),
]

MAX_STEPS = {"network_recon": 15, "vulnerability_exploit": 30, "ctf_capture": 50}
TOTAL_FLAGS = {"network_recon": 0, "vulnerability_exploit": 2, "ctf_capture": 3}


class Host:
    def __init__(self, ip, os_n, svcs, flag, req_root):
        self.ip = ip; self.os = os_n; self.svcs = svcs
        self.flag = flag; self.has_flag = bool(flag); self.req_root = req_root
        self.access = "none"; self.scanned = False

    def view(self) -> Dict[str, Any]:
        if not self.scanned:
            return {"ip": self.ip, "status": "unknown", "access": self.access}
        return {
            "ip": self.ip, "status": "online", "os": self.os,
            "open_ports": list(self.svcs.keys()),
            "services": {str(p): f"{s['n']} {s['v']}" for p, s in self.svcs.items()},
            "access": self.access,
        }


class NetworkSim:
    """Simulated corporate network for penetration testing RL."""

    def __init__(self, task_id: str = "network_recon", seed: int = 42):
        self.task_id = task_id
        self.rng = random.Random(seed)
        self.hosts: Dict[str, Host] = {}
        self.ids_level: float = 0.0
        self.captured_flags: List[str] = []
        self._build()

    def _build(self):
        flag_budget = TOTAL_FLAGS[self.task_id]
        fc = 0
        for ip, os_n, svcs, flag, req_root in NETWORK_TEMPLATE:
            use = bool(flag) and fc < flag_budget
            if use: fc += 1
            self.hosts[ip] = Host(ip, os_n, svcs, flag if use else "", req_root)

    # ── Actions ──────────────────────────────────────────────────────────────

    def scan(self, ip: str) -> Tuple[str, float]:
        if ip not in self.hosts:
            self._ids(0.05); return f"Host {ip} unreachable", -0.1
        h = self.hosts[ip]; self._ids(self.rng.uniform(0.08, 0.18))
        new = not h.scanned; h.scanned = True
        reward = 0.5 if new else 0.05
        svcs = ", ".join(f"{p}/{s['n']} {s['v']}" for p, s in h.svcs.items())
        return f"Scanned {ip} ({h.os}): {svcs}", reward

    def exploit(self, ip: str, technique: str) -> Tuple[str, float]:
        if ip not in self.hosts: self._ids(0.1); return f"{ip} not found", -0.2
        h = self.hosts[ip]
        if not h.scanned: return "Scan host first", -0.15
        matched = next((VULNS[s.get("vk", "")] for s in h.svcs.values()
                        if s.get("vk") and VULNS.get(s["vk"], {}).get("technique") == technique), None)
        if not matched: self._ids(0.2); return f"Technique '{technique}' N/A on {ip}", -0.1
        self._ids(matched["noise"])
        if self.rng.random() < matched["rate"]:
            g = matched["grant"]
            if g in ("user", "root"):
                prev = h.access
                if h.access == "none": h.access = g
                elif h.access == "user" and g == "root": h.access = "root"
                r = (1.5 if h.access == "root" else 1.0) * (1.0 if prev == "none" else 0.5)
                return f"[+] {matched['cve']} exploit SUCCESS on {ip} — got {h.access} shell", r
            return f"[+] Enum via {technique} on {ip}", 0.3
        return f"[-] Exploit failed on {ip} (IDS:{self.ids_level:.0%})", -0.05

    def brute_force(self, ip: str) -> Tuple[str, float]:
        if ip not in self.hosts or not self.hosts[ip].scanned:
            self._ids(0.15); return "Scan host first", -0.1
        self._ids(0.40); h = self.hosts[ip]
        if self.rng.random() < 0.30:
            h.access = "user"; return f"[+] Brute force SUCCESS on {ip} — user shell", 0.8
        return f"[-] Brute force failed (IDS:{self.ids_level:.0%})", -0.20

    def escalate(self, ip: str) -> Tuple[str, float]:
        if ip not in self.hosts: return "Host not found", -0.1
        h = self.hosts[ip]
        if h.access == "none": self._ids(0.12); return "Need shell first", -0.2
        if h.access == "root": return "Already root", 0.0
        self._ids(0.28)
        if self.rng.random() < 0.60:
            h.access = "root"; return f"[+] Privilege escalation SUCCESS on {ip} — root!", 1.2
        return f"[-] Escalation failed on {ip}", -0.10

    def exfiltrate(self, ip: str) -> Tuple[str, float]:
        if ip not in self.hosts: return "Host not found", -0.1
        h = self.hosts[ip]
        if h.access == "none": self._ids(0.08); return "No access to this host", -0.2
        self._ids(0.10)
        if not h.has_flag: return f"No flags on {ip}", 0.0
        if h.req_root and h.access != "root": return f"Root required to access flag on {ip}", -0.1
        flag = h.flag; h.has_flag = False; self.captured_flags.append(flag)
        return f"[+] FLAG CAPTURED on {ip}: {flag}", 2.5

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ids(self, delta: float):
        self.ids_level = min(1.0, self.ids_level + delta)

    @property
    def total_services(self) -> int:
        return sum(len(h.svcs) for h in self.hosts.values())

    @property
    def discovered_services(self) -> int:
        return sum(len(h.svcs) for h in self.hosts.values() if h.scanned)

    @property
    def compromised(self) -> List[str]:
        return [ip for ip, h in self.hosts.items() if h.access != "none"]

    def all_views(self) -> List[Dict[str, Any]]:
        return [h.view() for h in self.hosts.values()]
