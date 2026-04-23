import argparse
import json
import sys
from src.core.models import RepoTarget
from src.core.pipeline import Pipeline
from src.core.logger import logger


def main() -> None:
    """CLI entrypoint for Project Swarm repository scanning."""
    parser = argparse.ArgumentParser(
        description="Project Swarm — repository security scanner",
    )
    parser.add_argument("--repo", required=True, help="Repository URL to scan")
    parser.add_argument("--branch", default="main", help="Branch to scan (default: main)")
    parser.add_argument("--config", default=None, help="Path to scan config JSON file (optional)")
    args = parser.parse_args()

    try:
        scan_config: dict = {}
        if args.config:
            logger.debug("Loading scan config from %s", args.config)
            with open(args.config, "r") as f:
                scan_config = json.load(f)

        target = RepoTarget(url=args.repo, branch=args.branch, scan_config=scan_config)
        logger.debug("RepoTarget created: url=%s branch=%s", target.url, target.branch)

        result = Pipeline().run(target)
        logger.debug("Pipeline complete: verdict=%s", result.verdict)

        print(f"verdict:    {result.verdict}")
        print(f"report_id:  {result.id}")
        print(f"risk_notes: {result.risk_notes}")
        sys.exit(0 if result.verdict == "PASS" else 1)

    except Exception as exc:
        logger.debug("Unhandled exception: %s", exc, exc_info=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
