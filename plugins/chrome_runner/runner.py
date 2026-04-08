"""
KanGo Chrome Runner – Core Engine
──────────────────────────────────
Launches Chrome with a persistent profile + unpacked extensions.
Works on macOS (Chrome / Chrome Canary).
"""

import os
import sys
import json
import signal
import shutil
import subprocess
import platform
import time
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ── Paths ────────────────────────────────────────────────────────────────
CODING_ROOT = Path.home() / "Documents" / "Coding_space-Python"
PROFILES_ROOT = CODING_ROOT / "KanGo" / "plugins" / "chrome_runner" / "profiles"
PLUGIN_YAML = Path(__file__).parent / "plugins.yaml"

# iCloud target for downloads
ICLOUD_RUFUS_DB = (
    Path.home()
    / "Library"
    / "Mobile Documents"
    / "com~apple~CloudDocs"
    / "STRATOS X"
    / "Rufus_monitoring_DB"
)

# ── Chrome binary discovery (macOS) ─────────────────────────────────────
_CHROME_PATHS_MAC = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]


def find_chrome() -> str:
    """Return path to Chrome binary or raise."""
    if platform.system() != "Darwin":
        # Linux fallback
        for name in ("google-chrome", "google-chrome-stable", "chromium-browser"):
            path = shutil.which(name)
            if path:
                return path
        raise FileNotFoundError("Chrome not found on this system")

    for p in _CHROME_PATHS_MAC:
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "Chrome not found. Install Google Chrome or set CHROME_BIN env var."
    )


# ── Data classes ─────────────────────────────────────────────────────────
@dataclass
class PluginConfig:
    """One registered Chrome extension."""
    id: str
    name: str
    path: Path  # absolute path to unpacked extension
    description: str = ""
    start_url: str = ""
    profile: str = "default"
    enabled: bool = True


@dataclass
class ChromeSession:
    """A running Chrome instance."""
    profile: str
    plugins: list  # list of PluginConfig
    process: Optional[subprocess.Popen] = None
    pid: int = 0
    started_at: float = 0.0

    def is_alive(self) -> bool:
        if self.process:
            return self.process.poll() is None
        return False


# ── Registry ─────────────────────────────────────────────────────────────
def load_plugin_registry() -> dict:
    """Load plugins.yaml → dict of PluginConfig."""
    if not PLUGIN_YAML.exists():
        raise FileNotFoundError(f"Plugin registry not found: {PLUGIN_YAML}")
    with open(PLUGIN_YAML) as f:
        data = yaml.safe_load(f)

    registry = {}
    for pid, cfg in data.get("plugins", {}).items():
        ext_path = CODING_ROOT / cfg["path"]
        if not ext_path.exists():
            print(f"  ⚠️  Plugin '{pid}' path not found: {ext_path}")
            continue
        registry[pid] = PluginConfig(
            id=pid,
            name=cfg.get("name", pid),
            path=ext_path,
            description=cfg.get("description", ""),
            start_url=cfg.get("start_url", ""),
            profile=cfg.get("profile", data.get("default_profile", "default")),
            enabled=cfg.get("enabled", True),
        )
    return registry


# ── iCloud Symlink Setup ────────────────────────────────────────────────
def ensure_icloud_symlink(subfolder: str = "Category_SoV") -> Optional[Path]:
    """
    Create symlink: ~/Downloads/{subfolder} → iCloud/.../Rufus_monitoring_DB/{subfolder}
    so chrome.downloads automatically lands in iCloud.
    Returns the symlink path, or None if iCloud folder doesn't exist.
    """
    icloud_target = ICLOUD_RUFUS_DB / subfolder
    downloads_link = Path.home() / "Downloads" / subfolder

    if not ICLOUD_RUFUS_DB.parent.exists():
        print(f"  ⚠️  iCloud Drive folder not found — skipping symlink")
        return None

    # Create iCloud target folder
    icloud_target.mkdir(parents=True, exist_ok=True)

    # Create or verify symlink
    if downloads_link.is_symlink():
        if downloads_link.resolve() == icloud_target.resolve():
            return downloads_link  # already correct
        downloads_link.unlink()  # wrong target, recreate
    elif downloads_link.exists():
        # Real folder exists — migrate contents then replace with symlink
        print(f"  📦 Migrating existing {downloads_link} → iCloud...")
        for item in downloads_link.iterdir():
            dest = icloud_target / item.name
            if not dest.exists():
                shutil.move(str(item), str(dest))
        downloads_link.rmdir()

    downloads_link.symlink_to(icloud_target)
    print(f"  ☁️  Symlink: {downloads_link} → {icloud_target}")
    return downloads_link


# ═══════════════════════════════════════════════════════════════════════════
# ChromeRunner — Main Engine
# ═══════════════════════════════════════════════════════════════════════════
class ChromeRunner:
    """Launch and manage Chrome instances with extensions."""

    def __init__(self):
        self.chrome_bin = os.environ.get("CHROME_BIN") or find_chrome()
        self.registry = load_plugin_registry()
        self.sessions: dict[str, ChromeSession] = {}

    # ── List plugins ─────────────────────────────────────────────────────
    def list_plugins(self) -> list[PluginConfig]:
        return [p for p in self.registry.values() if p.enabled]

    def get_plugin(self, plugin_id: str) -> PluginConfig:
        if plugin_id not in self.registry:
            raise KeyError(
                f"Unknown plugin: '{plugin_id}'. "
                f"Available: {list(self.registry.keys())}"
            )
        return self.registry[plugin_id]

    # ── Build Chrome args ────────────────────────────────────────────────
    def _build_chrome_args(
        self,
        plugins: list[PluginConfig],
        profile: str,
        start_url: str = "",
        extra_args: list[str] | None = None,
    ) -> list[str]:
        """Build the full command-line for Chrome."""
        profile_dir = PROFILES_ROOT / profile
        profile_dir.mkdir(parents=True, exist_ok=True)

        # Collect extension paths
        ext_paths = ",".join(str(p.path) for p in plugins)

        args = [
            self.chrome_bin,
            f"--user-data-dir={profile_dir}",
            f"--load-extension={ext_paths}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-default-apps",
            "--disable-popup-blocking",
            # Keep extension dev mode warnings quiet
            "--disable-extensions-except=" + ext_paths,
            # Remote debugging port for future automation
            "--remote-debugging-port=9222",
        ]

        if extra_args:
            args.extend(extra_args)

        # Start URL
        url = start_url or plugins[0].start_url
        if url:
            args.append(url)

        return args

    # ── Launch ───────────────────────────────────────────────────────────
    def launch(
        self,
        plugin_ids: str | list[str],
        start_url: str = "",
        extra_args: list[str] | None = None,
        setup_icloud: bool = True,
    ) -> ChromeSession:
        """
        Launch Chrome with one or more plugins loaded.

        Args:
            plugin_ids: single ID or list of IDs from plugins.yaml
            start_url: override the default start URL
            extra_args: extra Chrome flags
            setup_icloud: create iCloud symlink for Downloads

        Returns:
            ChromeSession with the running process
        """
        if isinstance(plugin_ids, str):
            plugin_ids = [plugin_ids]

        plugins = [self.get_plugin(pid) for pid in plugin_ids]
        profile = plugins[0].profile

        # Check if profile already has a running session
        if profile in self.sessions and self.sessions[profile].is_alive():
            existing = self.sessions[profile]
            print(f"  ⚠️  Profile '{profile}' already running (PID {existing.pid})")
            print(f"      Stop it first with runner.stop('{profile}')")
            return existing

        # iCloud symlink (replaces the need for bridge server)
        if setup_icloud:
            ensure_icloud_symlink("Category_SoV")

        # Build and launch
        args = self._build_chrome_args(plugins, profile, start_url, extra_args)

        print(f"\n🚀 Launching Chrome")
        print(f"   Profile:    {profile}")
        print(f"   Extensions: {', '.join(p.name for p in plugins)}")
        if start_url or plugins[0].start_url:
            print(f"   URL:        {start_url or plugins[0].start_url}")
        print(f"   Debug:      http://localhost:9222")
        print()

        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # detach from terminal
        )

        session = ChromeSession(
            profile=profile,
            plugins=plugins,
            process=proc,
            pid=proc.pid,
            started_at=time.time(),
        )
        self.sessions[profile] = session

        print(f"   ✅ Chrome started (PID {proc.pid})")
        return session

    # ── Stop ─────────────────────────────────────────────────────────────
    def stop(self, profile: str = "") -> bool:
        """Stop a Chrome session by profile name."""
        if not profile:
            # Stop all
            for p in list(self.sessions.keys()):
                self.stop(p)
            return True

        sess = self.sessions.get(profile)
        if not sess or not sess.is_alive():
            print(f"  ℹ️  No running session for profile '{profile}'")
            self.sessions.pop(profile, None)
            return False

        print(f"  🛑 Stopping Chrome (PID {sess.pid}, profile '{profile}')...")
        try:
            os.killpg(os.getpgid(sess.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            sess.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(sess.pid), signal.SIGKILL)
        self.sessions.pop(profile, None)
        print(f"  ✅ Stopped.")
        return True

    # ── Status ───────────────────────────────────────────────────────────
    def status(self) -> list[dict]:
        """Return status of all sessions."""
        result = []
        for prof, sess in list(self.sessions.items()):
            alive = sess.is_alive()
            if not alive:
                self.sessions.pop(prof, None)
            result.append({
                "profile": prof,
                "pid": sess.pid,
                "alive": alive,
                "plugins": [p.name for p in sess.plugins],
                "uptime_min": round((time.time() - sess.started_at) / 60, 1)
                if alive else 0,
            })
        return result

    # ── Clean profile ────────────────────────────────────────────────────
    def clean_profile(self, profile: str) -> bool:
        """Delete a Chrome profile directory (fresh start)."""
        self.stop(profile)
        profile_dir = PROFILES_ROOT / profile
        if profile_dir.exists():
            shutil.rmtree(profile_dir)
            print(f"  🗑️  Deleted profile: {profile_dir}")
            return True
        print(f"  ℹ️  Profile not found: {profile}")
        return False
