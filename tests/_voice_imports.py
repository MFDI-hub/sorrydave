"""Load discordy_media.voice modules without importing the full voice package."""

from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VOICE_DIR = _REPO_ROOT / "discordy_media" / "voice"


def _ensure_package(name: str, path: Path) -> types.ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    module = types.ModuleType(name)
    module.__path__ = [str(path)]
    module.__package__ = name
    sys.modules[name] = module
    return module


def _install_discordy_stubs() -> None:
    _ensure_package("discordy_media", _REPO_ROOT / "discordy_media")
    _ensure_package("discordy_media.voice", _VOICE_DIR)

    if "discordy_media.Logger" not in sys.modules:
        logger_mod = types.ModuleType("discordy_media.Logger")

        class MyLogger:
            @staticmethod
            def class_logger(name: str) -> logging.Logger:
                return logging.getLogger(name)

        logger_mod.MyLogger = MyLogger
        sys.modules["discordy_media.Logger"] = logger_mod

    if "discordy_media.doh_bypass" not in sys.modules:
        doh = types.ModuleType("discordy_media.doh_bypass")

        async def connect_ws_with_bypass(*_args, **_kwargs):
            raise RuntimeError("connect_ws_with_bypass is not used in unit tests")

        doh.connect_ws_with_bypass = connect_ws_with_bypass
        doh.doh_bypass_from_runtime = lambda *_args, **_kwargs: None
        sys.modules["discordy_media.doh_bypass"] = doh

    if "curl_cffi" not in sys.modules:
        try:
            import curl_cffi  # noqa: F401
        except ImportError:
            curl_cffi = types.ModuleType("curl_cffi")
            curl_cffi.CurlError = Exception
            sys.modules["curl_cffi"] = curl_cffi
            requests_mod = types.ModuleType("curl_cffi.requests")

            class AsyncSession:
                pass

            class AsyncWebSocket:
                pass

            requests_mod.AsyncSession = AsyncSession
            requests_mod.AsyncWebSocket = AsyncWebSocket
            sys.modules["curl_cffi.requests"] = requests_mod


def load_voice_module(module_name: str):
    """Import discordy_media.voice.<module_name> from source without package side effects."""
    _install_discordy_stubs()
    full_name = f"discordy_media.voice.{module_name}"
    existing = sys.modules.get(full_name)
    if existing is not None and getattr(existing, "__file__", None):
        return existing
    path = _VOICE_DIR / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(full_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {full_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module
