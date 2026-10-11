"""Start P2PChat using the compiled client extension when available."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_client_module():
    """Load client.pyd first, falling back to client.py for development."""
    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    compiled = next(
        (path for suffix in suffixes for path in ROOT.glob(f"client{suffix}")),
        None,
    )
    if compiled is not None:
        spec = importlib.util.spec_from_file_location("client", compiled)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load the compiled client: {compiled}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["client"] = module
        spec.loader.exec_module(module)
        print(f"P2PChat: using compiled client {compiled.name}")
        return module

    print("P2PChat: no .pyd found, using client.py (run setup.py to compile first)")
    import client

    return client


if __name__ == "__main__":
    client = load_client_module()
    raise SystemExit(client.main())
