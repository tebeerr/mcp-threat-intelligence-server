"""Download the MITRE ATT&CK Enterprise STIX bundle used by the local catalog."""

import asyncio
import os
from pathlib import Path
import sys

import httpx

from ti_mcp.config import Settings, load_env_file
from ti_mcp.connectors.attack import load_techniques
from ti_mcp.domain.errors import ServiceError

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


async def sync_attack_bundle(target: Path, client: httpx.AsyncClient | None = None) -> int:
    """Replace `target` only once the download is proven usable. Returns technique count."""
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".partial")
    http = client or httpx.AsyncClient(timeout=120, follow_redirects=False)
    try:
        async with http.stream("GET", ATTACK_BUNDLE_URL) as response:
            response.raise_for_status()
            with partial.open("wb") as output:
                async for chunk in response.aiter_bytes():
                    output.write(chunk)
        techniques = await asyncio.to_thread(load_techniques, partial)
        if not techniques:
            raise ServiceError("SOURCE_UNAVAILABLE", "Downloaded bundle has no ATT&CK techniques")
        os.replace(partial, target)
        return len(techniques)
    finally:
        partial.unlink(missing_ok=True)
        if client is None:
            await http.aclose()


def main() -> None:
    load_env_file()
    target = Settings.from_env().attack_stix_path
    try:
        count = asyncio.run(sync_attack_bundle(target))
    except (httpx.HTTPError, ServiceError, OSError) as exc:
        print(f"ATT&CK sync failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"{count} ATT&CK techniques saved to {target}")


if __name__ == "__main__":
    main()
