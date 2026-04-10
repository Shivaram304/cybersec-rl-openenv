"""FastAPI app for AutoPloit environment."""

from openenv.core.env_server.http_server import create_app

try:
    from ..models import AutoPloitAction, AutoPloitObservation
    from .autoploit_environment import AutoPloitEnvironment
except ImportError:
    from models import AutoPloitAction, AutoPloitObservation
    from server.autoploit_environment import AutoPloitEnvironment

app = create_app(
    AutoPloitEnvironment,
    AutoPloitAction,
    AutoPloitObservation,
    env_name="autoploit",
    max_concurrent_envs=10,
)


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
