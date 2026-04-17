"""
SIGINTX — Ollama Manager
Fully automatic Ollama lifecycle: install → serve → pull model.

On every backend startup this module:
  1. Detects whether `ollama` is installed on the OS.
  2. If not installed, downloads and runs the official silent installer.
  3. Starts `ollama serve` as a background subprocess (if not already running).
  4. Pulls the default model if it is not already present.

No user interaction is required at any point.
"""

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

import httpx

logger = logging.getLogger("sigintx.ollama_manager")

# ── Constants ─────────────────────────────────────────────────────────────────

# If OLLAMA_HOST env var is set, use it (supports Cloudflare tunnel / remote host).
# Otherwise default to local.
_env_host = os.getenv("OLLAMA_HOST", "").strip().rstrip("/")
OLLAMA_HOST   = _env_host if _env_host else "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"   # small enough for CPU-only machines

# True when OLLAMA_HOST points to a remote server — skip local install/start.
_IS_REMOTE = bool(_env_host) and not any(
    OLLAMA_HOST.startswith(p)
    for p in ("http://localhost", "http://127.", "http://::1", "http://0.0.0.0")
)

# Per-OS silent installer locations
_INSTALL_URLS = {
    "Windows": "https://ollama.com/download/OllamaSetup.exe",
    "Darwin":  "https://ollama.com/download/Ollama-darwin.zip",
    "Linux":   None,   # handled via curl install script
}

# ── Setup-status registry (read by /api/v1/ollama/setup-status) ───────────────

setup_status: dict = {
    "stage":    "starting",   # starting | installing | serving | pulling | ready | error
    "message":  "Initializing AI engine…",
    "progress": 0,            # 0-100
    "model":    DEFAULT_MODEL,
    "error":    None,
}


def _set_status(stage: str, message: str, progress: int, error: Optional[str] = None) -> None:
    setup_status.update(stage=stage, message=message, progress=progress, error=error)
    logger.info("[ollama_manager] %s — %s", stage.upper(), message)


# ── Step 1: detect ────────────────────────────────────────────────────────────

def _ollama_binary() -> Optional[str]:
    """Return path to the ollama executable, or None if not found."""
    path = shutil.which("ollama")
    if path:
        return path
    # Common non-PATH locations
    candidates = []
    sys_os = platform.system()
    if sys_os == "Windows":
        candidates = [
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"),
            os.path.expandvars(r"%PROGRAMFILES%\Ollama\ollama.exe"),
        ]
    elif sys_os == "Darwin":
        candidates = ["/usr/local/bin/ollama", "/Applications/Ollama.app/Contents/MacOS/ollama"]
    else:  # Linux
        candidates = ["/usr/local/bin/ollama", "/usr/bin/ollama", os.path.expanduser("~/.local/bin/ollama")]

    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ── Step 2: install ───────────────────────────────────────────────────────────

async def _install_ollama() -> bool:
    """Download and silently install Ollama. Returns True on success."""
    sys_os = platform.system()
    _set_status("installing", f"Installing Ollama on {sys_os}…", 10)

    try:
        if sys_os == "Linux":
            return await _install_linux()
        elif sys_os == "Windows":
            return await _install_windows()
        elif sys_os == "Darwin":
            return await _install_macos()
        else:
            _set_status("error", f"Unsupported OS: {sys_os}", 0, f"Unsupported OS: {sys_os}")
            return False
    except Exception as exc:
        _set_status("error", f"Install failed: {exc}", 0, str(exc))
        logger.exception("[ollama_manager] Install exception")
        return False


async def _install_linux() -> bool:
    """curl -fsSL https://ollama.com/install.sh | sh"""
    _set_status("installing", "Running Ollama install script (Linux)…", 15)
    proc = await asyncio.create_subprocess_shell(
        "curl -fsSL https://ollama.com/install.sh | sh",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    if proc.returncode == 0:
        logger.info("[ollama_manager] Linux install stdout:\n%s", out.decode(errors="replace")[-2000:])
        return True
    logger.error("[ollama_manager] Linux install failed (rc=%d):\n%s", proc.returncode, out.decode(errors="replace")[-2000:])
    return False


async def _install_windows() -> bool:
    """Download OllamaSetup.exe and run it with /S (silent)."""
    url  = _INSTALL_URLS["Windows"]
    dest = os.path.join(tempfile.gettempdir(), "OllamaSetup.exe")

    _set_status("installing", "Downloading Ollama installer (Windows)…", 12)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = 12 + int((downloaded / total) * 18)
                        setup_status["progress"] = pct

    _set_status("installing", "Running Ollama installer silently…", 30)
    proc = await asyncio.create_subprocess_exec(
        dest, "/S",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await asyncio.wait_for(proc.communicate(), timeout=180)
    os.unlink(dest)

    # Refresh PATH so the new binary is found
    if proc.returncode == 0:
        # Windows installer adds to PATH; update os.environ for this process
        local_app = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama")
        if local_app not in os.environ.get("PATH", ""):
            os.environ["PATH"] = local_app + os.pathsep + os.environ.get("PATH", "")
        return True
    logger.error("[ollama_manager] Windows installer returned %d", proc.returncode)
    return False


async def _install_macos() -> bool:
    """Download Ollama.app zip, unzip to /Applications, symlink binary."""
    import zipfile
    url  = _INSTALL_URLS["Darwin"]
    dest = os.path.join(tempfile.gettempdir(), "Ollama-darwin.zip")

    _set_status("installing", "Downloading Ollama for macOS…", 12)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = 12 + int((downloaded / total) * 18)
                        setup_status["progress"] = pct

    _set_status("installing", "Extracting Ollama.app…", 32)
    with zipfile.ZipFile(dest, "r") as z:
        z.extractall("/Applications")
    os.unlink(dest)

    # Create CLI symlink
    cli_src = "/Applications/Ollama.app/Contents/Resources/ollama"
    cli_dst = "/usr/local/bin/ollama"
    if os.path.isfile(cli_src) and not os.path.exists(cli_dst):
        try:
            os.symlink(cli_src, cli_dst)
        except PermissionError:
            # Try sudo-less alternative path
            local_bin = os.path.expanduser("~/.local/bin")
            os.makedirs(local_bin, exist_ok=True)
            os.symlink(cli_src, os.path.join(local_bin, "ollama"))
            os.environ["PATH"] = local_bin + os.pathsep + os.environ.get("PATH", "")
    return True


# ── Step 3: serve ─────────────────────────────────────────────────────────────

_serve_process: Optional[asyncio.subprocess.Process] = None


async def _is_server_running() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OLLAMA_HOST}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


async def _start_server(binary: str) -> bool:
    """Start `ollama serve` as a detached background process."""
    global _serve_process

    if await _is_server_running():
        logger.info("[ollama_manager] Ollama server already running")
        return True

    _set_status("serving", "Starting Ollama server…", 45)

    env = os.environ.copy()
    env["OLLAMA_HOST"] = "0.0.0.0:11434"   # listen on all interfaces

    kwargs: dict = {
        "stdout": asyncio.subprocess.DEVNULL,
        "stderr": asyncio.subprocess.DEVNULL,
        "env": env,
    }

    # On Windows we need CREATE_NO_WINDOW + detach
    if platform.system() == "Windows":
        kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW |        # no console window
            subprocess.CREATE_NEW_PROCESS_GROUP  # detach from our process
        )
        # On Windows, use the exe path directly
        binary_cmd = [binary, "serve"]
    else:
        binary_cmd = [binary, "serve"]

    try:
        _serve_process = await asyncio.create_subprocess_exec(*binary_cmd, **kwargs)
        logger.info("[ollama_manager] Launched ollama serve (pid=%s)", _serve_process.pid)
    except Exception as exc:
        logger.error("[ollama_manager] Failed to launch ollama serve: %s", exc)
        return False

    # Wait up to 30 seconds for it to answer
    for attempt in range(30):
        await asyncio.sleep(1)
        if await _is_server_running():
            logger.info("[ollama_manager] Ollama server ready after %ds", attempt + 1)
            return True
        setup_status["progress"] = 45 + attempt
    logger.error("[ollama_manager] Server did not become ready in 30s")
    return False


# ── Step 4: pull ──────────────────────────────────────────────────────────────

async def _pull_model(model: str) -> bool:
    """Pull a model via the Ollama REST API. Streams progress."""
    # Check if already installed
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{OLLAMA_HOST}/api/tags")
            if r.status_code == 200:
                installed = {m["name"] for m in r.json().get("models", [])}
                base = model.split(":")[0]
                if any(m == model or m.startswith(base) for m in installed):
                    logger.info("[ollama_manager] Model '%s' already installed", model)
                    return True
    except Exception:
        pass

    _set_status("pulling", f"Downloading model {model}…  (this may take a few minutes)", 78)

    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            async with client.stream(
                "POST",
                f"{OLLAMA_HOST}/api/pull",
                json={"name": model, "stream": True},
                timeout=httpx.Timeout(600.0, connect=10.0),
            ) as resp:
                if not resp.is_success:
                    body = await resp.aread()
                    logger.error("[ollama_manager] Pull HTTP %d: %s", resp.status_code, body[:200])
                    return False

                async for raw in resp.aiter_lines():
                    if not raw:
                        continue
                    try:
                        data = json_loads_safe(raw)
                        if not data:
                            continue
                        if "error" in data:
                            logger.error("[ollama_manager] Pull error: %s", data["error"])
                            return False
                        status = data.get("status", "")
                        completed = data.get("completed", 0)
                        total     = data.get("total", 0)
                        if total and completed:
                            pct = 78 + int((completed / total) * 20)
                            setup_status["progress"] = min(pct, 97)
                        if status:
                            setup_status["message"] = f"Pulling {model}: {status}"
                        if status == "success":
                            return True
                    except Exception:
                        pass
        return True   # stream finished without explicit success — assume ok
    except Exception as exc:
        logger.error("[ollama_manager] Pull exception: %s", exc)
        return False


def json_loads_safe(s: str) -> Optional[dict]:
    import json
    try:
        return json.loads(s)
    except Exception:
        return None


# ── Public entry point ────────────────────────────────────────────────────────

async def ensure_ollama_ready() -> None:
    """
    Full lifecycle:
      detect → (install if missing) → start server → pull model → ready

    When OLLAMA_HOST points to a remote server (e.g. a Cloudflare tunnel),
    skip the local install/start steps and just verify the remote is reachable.

    Runs as a background asyncio task from main.py lifespan.
    Status is exposed via setup_status dict (polled by the frontend).
    """
    model = DEFAULT_MODEL

    # ── Remote host path (Cloudflare tunnel / external Ollama) ────────────────
    if _IS_REMOTE:
        _set_status("starting", f"Using remote Ollama at {OLLAMA_HOST}…", 20)
        if not await _is_server_running():
            _set_status(
                "error",
                f"Remote Ollama at {OLLAMA_HOST} is not reachable. "
                "Check your tunnel is running and OLLAMA_HOST is correct.",
                0,
                "Remote Ollama unreachable",
            )
            return
        _set_status("pulling", f"Remote server reachable. Checking model {model}…", 75)
        ok = await _pull_model(model)
        if not ok:
            _set_status("error", f"Failed to pull model {model} on remote host.", 0, f"Model pull failed: {model}")
            return
        _set_status("ready", f"AI ready — {model} on {OLLAMA_HOST}", 100)
        return

    # ── Local host path (default, auto-install) ───────────────────────────────
    _set_status("starting", "Checking for Ollama installation…", 5)

    # ── 1. Find or install binary ─────────────────────────────────────────────
    binary = _ollama_binary()
    if not binary:
        _set_status("installing", "Ollama not found — installing automatically…", 8)
        ok = await _install_ollama()
        if not ok:
            _set_status("error", "Ollama installation failed. Check logs.", 0, "Installation failed")
            return
        binary = _ollama_binary()
        if not binary:
            _set_status("error", "Ollama binary not found after install. Restart may be needed.", 0, "Binary not found post-install")
            return
        _set_status("installing", "Ollama installed successfully.", 40)

    else:
        _set_status("serving", "Ollama found — starting server…", 40)

    # ── 2. Start server ───────────────────────────────────────────────────────
    ok = await _start_server(binary)
    if not ok:
        _set_status("error", "Failed to start Ollama server. Check system logs.", 0, "Server start failed")
        return

    _set_status("pulling", f"Server ready. Checking model {model}…", 75)

    # ── 3. Pull model ─────────────────────────────────────────────────────────
    ok = await _pull_model(model)
    if not ok:
        _set_status("error", f"Failed to pull model {model}.", 0, f"Model pull failed: {model}")
        return

    # ── Done ──────────────────────────────────────────────────────────────────
    _set_status("ready", f"AI ready — {model} on {OLLAMA_HOST}", 100)
