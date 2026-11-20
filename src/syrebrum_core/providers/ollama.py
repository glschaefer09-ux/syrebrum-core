# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Local model adapter for Ollama (https://ollama.com).

Safe defaults: loopback only, a request budget, a size cap on prompts and
replies, and a timeout. Remote hosts need allow_remote=True explicitly.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import threading
import urllib.error
import urllib.parse
import urllib.request

from ..contracts import ContractError, check_id, json_depth_ok

MAX_PROMPT_CHARS = 32_000
MAX_REPLY_BYTES = 1_000_000


class BudgetExceeded(RuntimeError):
    pass


class ProviderError(RuntimeError):
    pass


class OllamaProvider:
    def __init__(self, base_url: str = "http://127.0.0.1:11434", *, max_calls: int = 100,
                 timeout_s: float = 120.0, allow_remote: bool = False) -> None:
        if type(allow_remote) is not bool:
            raise ContractError("allow_remote must be True or False (parse config strings yourself)")
        self.base_url = _canonical_base_url(base_url, allow_remote)
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or not 1 <= max_calls <= 100_000:
            raise ContractError("max_calls must be between 1 and 100000")
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= 600:
            raise ContractError("timeout_s must be a number from 0 to 600 seconds")
        self.max_calls, self.calls, self.timeout_s = max_calls, 0, float(timeout_s)  # timeout is per socket operation
        self._budget_lock = threading.Lock()

    def generate(self, model: str, prompt: str) -> str:
        check_id("model", model)
        if not isinstance(prompt, str) or not prompt or len(prompt) > MAX_PROMPT_CHARS:
            raise ContractError(f"prompt must be 1-{MAX_PROMPT_CHARS} characters")
        with self._budget_lock:
            if self.calls >= self.max_calls:
                raise BudgetExceeded(f"call budget of {self.max_calls} used up")
            self.calls += 1
        body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(self.base_url + "/api/generate", data=body,  # noqa: S310 - http(s) only, checked in __init__
                                     headers={"Content-Type": "application/json"}, method="POST")
        # No proxies (an HTTP(S)_PROXY setting would send the prompt off the machine) and no redirects.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout_s) as resp:
                raw = resp.read(MAX_REPLY_BYTES + 1)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from None
        if len(raw) > MAX_REPLY_BYTES:
            raise ProviderError("Ollama reply too large")
        try:
            body = raw.decode("utf-8")  # strict: the depth check and the parser must see the same text
        except UnicodeDecodeError:
            raise ProviderError("Ollama reply was not UTF-8") from None
        if not json_depth_ok(body, 8):
            raise ProviderError("Ollama reply is nested too deeply")
        try:
            text = json.loads(body)["response"]
        except (ValueError, KeyError, TypeError, RecursionError):
            raise ProviderError("Ollama reply was not understood") from None
        if not isinstance(text, str):
            raise ProviderError("Ollama reply was not text")
        return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _canonical_base_url(base_url: str, allow_remote: bool) -> str:
    """Rebuild the URL from validated parts; never pass the raw string through."""
    if (not isinstance(base_url, str) or len(base_url) > 2048
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base_url)
            or "\\" in base_url or "%" in base_url):
        raise ContractError("base_url must be a short URL without spaces, control characters, \\ or %")
    try:
        u = urllib.parse.urlparse(base_url)
        port = u.port
    except ValueError:
        raise ContractError("base_url has an invalid port") from None
    if (u.scheme not in ("http", "https") or not u.hostname or u.username is not None
            or u.password is not None or "@" in u.netloc or u.path not in ("", "/") or u.params
            or u.query or u.fragment or "?" in base_url or "#" in base_url or ";" in base_url):
        raise ContractError("base_url must be http(s)://host[:port] with nothing else")
    if port == 0:
        raise ContractError("base_url port must be 1-65535")
    host = u.hostname  # already lower-cased
    if host == "localhost":
        host = "127.0.0.1"  # don't depend on the resolver
    if not allow_remote and not _is_loopback(host):
        raise ContractError("Ollama host is not on this machine; pass allow_remote=True to permit it")
    shown = f"[{host}]" if ":" in host else host
    return f"{u.scheme}://{shown}" + (f":{port}" if port else "")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:  # literal IPs only: names such as 127.0.0.1.nip.io are refused
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
