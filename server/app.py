"""FastAPI app for NetPwn environment."""

from openenv.core.env_server.http_server import create_app

try:
    from ..models import NetPwnAction, NetPwnObservation
    from .netpwn_environment import NetPwnEnvironment
except ImportError:
    from models import NetPwnAction, NetPwnObservation
    from server.netpwn_environment import NetPwnEnvironment

app = create_app(
    NetPwnEnvironment,
    NetPwnAction,
    NetPwnObservation,
    env_name="netpwn",
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
