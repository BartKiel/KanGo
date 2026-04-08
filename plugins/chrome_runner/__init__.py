"""
KanGo Chrome Runner – Plugin Launcher Module
─────────────────────────────────────────────
Launches a real Chrome browser with a persistent profile and one or more
unpacked Chrome extensions pre-loaded.

Features:
  • Dedicated Chrome profile per session (persists cookies, history, login state)
  • Auto-discovers registered extensions from plugins.yaml
  • Can run headless (for CI) or headed (normal)
  • Exposes simple API: start / stop / status / list-plugins
  • iCloud symlink support – Downloads automatically land in iCloud

Usage (CLI):
  python -m plugins.chrome_runner                          # interactive menu
  python -m plugins.chrome_runner --plugin sov_listener    # launch specific plugin
  python -m plugins.chrome_runner --list                   # list registered plugins

Usage (from KanGo app.py):
  from plugins.chrome_runner import ChromeRunner
  runner = ChromeRunner()
  runner.launch("sov_listener")
"""
