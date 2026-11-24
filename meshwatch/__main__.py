"""Run with: python -m meshwatch"""
import logging

import uvicorn

from .app import create_app
from .config import Env


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("meshcore").setLevel(logging.WARNING)
    env = Env.load()
    uvicorn.run(create_app(env), host=env.host, port=env.port, proxy_headers=True,
                forwarded_allow_ips="127.0.0.1", log_level="warning")


if __name__ == "__main__":
    main()
