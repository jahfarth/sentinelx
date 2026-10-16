"""Entry point: ``python -m sentinelx.agent --config agent.yml``."""

import argparse
import logging
import signal

from sentinelx.agent.shipper import AgentConfig, Shipper

log = logging.getLogger(__name__)


def main() -> None:
    """Parse args, load config, run the shipper until interrupted."""
    parser = argparse.ArgumentParser(description="SentinelX log shipper agent")
    parser.add_argument("--config", required=True, help="Path to agent YAML config file")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config = AgentConfig.from_yaml(args.config)
    log.info("starting shipper for %d file(s) -> %s", len(config.files), config.api_url)

    stop = False

    def _handle(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    shipper = Shipper(config)
    try:
        while not stop:
            shipper.run(max_cycles=1)
    except KeyboardInterrupt:
        pass
    log.info("shipper stopped")


if __name__ == "__main__":
    main()
