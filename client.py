"""NetPwn Environment Client."""
from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

try:
    from .models import NetPwnAction, NetPwnObservation
except ImportError:
    from models import NetPwnAction, NetPwnObservation


class NetPwnEnv(EnvClient[NetPwnAction, NetPwnObservation, State]):
    """
    Client for the NetPwn penetration testing environment.

    Example (Docker):
        env = await NetPwnEnv.from_docker_image("netpwn_env:latest")
        result = await env.reset()
        result = await env.step(NetPwnAction(action_type="scan", target_ip="192.168.1.1"))

    Example (URL):
        env = NetPwnEnv(base_url="http://localhost:8000")
        result = env.reset()
    """

    def _step_payload(self, action: NetPwnAction) -> Dict:
        return {
            "action_type": action.action_type,
            "target_ip":   action.target_ip,
            "technique":   action.technique,
        }

    def _parse_result(self, payload: Dict) -> StepResult[NetPwnObservation]:
        obs_data = payload.get("observation", {})
        observation = NetPwnObservation(
            known_hosts=obs_data.get("known_hosts", []),
            current_pos=obs_data.get("current_pos", "external"),
            ids_alert=obs_data.get("ids_alert", 0.0),
            flags_captured=obs_data.get("flags_captured", 0),
            action_result=obs_data.get("action_result", ""),
            step_info=obs_data.get("step_info", ""),
            done=payload.get("done", False),
            reward=payload.get("reward", 0.0),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id", ""),
            step_count=payload.get("step_count", 0),
        )
