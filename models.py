"""
AutoPloit — Penetration Testing RL Environment
Models using the correct OpenEnv Pydantic API.

Meta × PyTorch OpenEnv Hackathon
"""
from typing import Any, Dict, List
from pydantic import Field
from openenv.core.env_server.types import Action, Observation


class AutoPloitAction(Action):
    """
    Agent action in the AutoPloit penetration testing environment.

    action_type: "scan" | "exploit" | "brute_force" | "escalate" | "exfiltrate"
    target_ip:   Target host IP address (192.168.1.1 – 192.168.1.7)
    technique:   CVE technique for exploit actions
                 "cve_2021_41773" | "ftp_backdoor" | "eternal_blue" |
                 "sql_injection"  | "ssh_enum"
    """
    action_type: str = Field(default="scan",          description="Action type: scan | exploit | brute_force | escalate | exfiltrate")
    target_ip:   str = Field(default="192.168.1.1",   description="Target host IP in 192.168.1.0/24")
    technique:   str = Field(default="",              description="CVE exploit technique (required for exploit action)")


class AutoPloitObservation(Observation):
    """
    Observation returned after each environment step.

    known_hosts:    List of host dicts visible to the agent
    current_pos:    IP the agent currently operates from ("external" = not inside yet)
    ids_alert:      IDS suspicion level [0.0–1.0] (above 0.8 = critical)
    flags_captured: Number of CTF flags found
    action_result:  Plain-text result of the last action
    step_info:      Natural-language pentest narrative (used by LLM evaluator)
    """
    known_hosts:    List[Dict[str, Any]] = Field(default_factory=list, description="Visible host info")
    current_pos:    str   = Field(default="external",  description="Current attacker position")
    ids_alert:      float = Field(default=0.0,         description="IDS alert level [0.0–1.0]")
    flags_captured: int   = Field(default=0,           description="Flags captured so far")
    action_result:  str   = Field(default="",          description="Result of the last action")
    step_info:      str   = Field(default="",          description="Natural-language step narrative")
