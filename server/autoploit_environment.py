"""
AutoPloit Environment — OpenEnv implementation.
Uses the correct openenv.core.env_server API.
"""
import random
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import AutoPloitAction, AutoPloitObservation
    from .network_simulator import NetworkSim, MAX_STEPS, TOTAL_FLAGS
except ImportError:
    from models import AutoPloitAction, AutoPloitObservation
    from server.network_simulator import NetworkSim, MAX_STEPS, TOTAL_FLAGS


class AutoPloitEnvironment(Environment):
    """
    AutoPloit: A penetration testing RL environment.

    Three tasks with increasing difficulty:
      network_recon       (Easy)   — Discover all hosts and services
      vulnerability_exploit (Medium) — Exploit CVE vulnerabilities for system access
      ctf_capture         (Hard)   — Full attack chain: recon → exploit → privesc → flag capture

    The agent performs actions against a simulated corporate network and must
    balance attack success with IDS evasion.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, task_id: str = "network_recon"):
        self.task_id = task_id
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._net: NetworkSim = NetworkSim(task_id=task_id)
        self._max_steps = MAX_STEPS[task_id]
        self._total_flags = TOTAL_FLAGS[task_id]

    def reset(self) -> AutoPloitObservation:
        seed = random.randint(0, 99_999)
        self._net = NetworkSim(task_id=self.task_id, seed=seed)
        self._state = State(episode_id=str(uuid4()), step_count=0)

        return AutoPloitObservation(
            known_hosts=[{"ip": ip, "status": "unknown"} for ip in self._net.hosts],
            current_pos="external",
            ids_alert=0.0,
            flags_captured=0,
            action_result="Environment ready. You are an external attacker targeting 192.168.1.0/24.",
            step_info=(
                f"[RESET] Task '{self.task_id}' started. "
                f"{len(self._net.hosts)} hosts in subnet. "
                f"Flags to capture: {self._total_flags}. Begin with 'scan'."
            ),
            done=False,
            reward=0.0,
        )

    def step(self, action: AutoPloitAction) -> AutoPloitObservation:  # type: ignore[override]
        self._state.step_count += 1
        msg, reward = self._dispatch(action)

        # IDS critical penalty
        if self._net.ids_level >= 0.80:
            reward -= 0.5
            msg += " ⚠️ IDS CRITICAL — detection imminent!"

        flags = len(self._net.captured_flags)
        done = (
            self._state.step_count >= self._max_steps
            or self._net.ids_level >= 0.98
            or (self.task_id == "network_recon" and self._net.discovered_services >= self._net.total_services)
            or (self._total_flags > 0 and flags >= self._total_flags)
        )

        step_info = (
            f"Step {self._state.step_count}: '{action.action_type}' on {action.target_ip}"
            + (f" [{action.technique}]" if action.technique else "")
            + f" → {msg[:80]}. "
            f"Reward: {reward:+.3f}. IDS: {self._net.ids_level:.0%}. "
            f"Flags: {flags}/{self._total_flags}. "
            f"Compromised: {len(self._net.compromised)}/{len(self._net.hosts)}."
        )

        return AutoPloitObservation(
            known_hosts=self._net.all_views(),
            current_pos=action.target_ip,
            ids_alert=round(self._net.ids_level, 3),
            flags_captured=flags,
            action_result=msg,
            step_info=step_info,
            done=done,
            reward=round(reward, 4),
            metadata={
                "step_count": self._state.step_count,
                "compromised": self._net.compromised,
                "discovered_services": self._net.discovered_services,
                "total_services": self._net.total_services,
                "task_id": self.task_id,
            },
        )

    @property
    def state(self) -> State:
        return self._state

    # ── Action dispatcher ────────────────────────────────────────────────────

    def _dispatch(self, action: AutoPloitAction):
        t = action.action_type.lower().strip()
        ip = action.target_ip
        if t == "scan":        return self._net.scan(ip)
        if t == "exploit":     return self._net.exploit(ip, action.technique)
        if t == "brute_force": return self._net.brute_force(ip)
        if t == "escalate":    return self._net.escalate(ip)
        if t == "exfiltrate":  return self._net.exfiltrate(ip)
        self._net._ids(0.05)
        return f"Unknown action '{t}'. Valid: scan|exploit|brute_force|escalate|exfiltrate", -0.1
