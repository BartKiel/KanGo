#!/usr/bin/env python3
"""
KanGo Chrome Runner – CLI
──────────────────────────
  python -m plugins.chrome_runner                # interactive menu
  python -m plugins.chrome_runner --list         # list plugins
  python -m plugins.chrome_runner --plugin sov_listener
  python -m plugins.chrome_runner --plugin sov_listener,pill_harvester
  python -m plugins.chrome_runner --stop         # stop all sessions
  python -m plugins.chrome_runner --status       # show running sessions
  python -m plugins.chrome_runner --clean-profile stratosx_harvest
"""

import argparse
import sys
from .runner import ChromeRunner


def interactive_menu(runner: ChromeRunner):
    """Simple TUI menu to pick and launch plugins."""
    plugins = runner.list_plugins()
    if not plugins:
        print("No enabled plugins found in plugins.yaml")
        return

    print()
    print("═" * 56)
    print("  KanGo Chrome Runner — Plugin Launcher")
    print("═" * 56)
    print()

    for i, p in enumerate(plugins, 1):
        marker = "✅" if p.enabled else "⛔"
        print(f"  {i}. {marker} {p.name}")
        print(f"     {p.description}")
        print()

    print(f"  A. Launch ALL enabled plugins together")
    print(f"  S. Show status of running sessions")
    print(f"  X. Stop all and exit")
    print()

    choice = input("  Choose (number / A / S / X): ").strip()

    if choice.upper() == "X":
        runner.stop()
        return
    elif choice.upper() == "S":
        status = runner.status()
        if not status:
            print("\n  No running sessions.")
        for s in status:
            alive = "🟢" if s["alive"] else "🔴"
            print(
                f"  {alive} {s['profile']} "
                f"(PID {s['pid']}) — "
                f"{', '.join(s['plugins'])} — "
                f"{s['uptime_min']} min"
            )
        return
    elif choice.upper() == "A":
        ids = [p.id for p in plugins]
        runner.launch(ids)
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(plugins):
            runner.launch(plugins[idx].id)
        else:
            print(f"  ❌ Invalid choice: {choice}")
    except ValueError:
        print(f"  ❌ Invalid choice: {choice}")


def main():
    parser = argparse.ArgumentParser(
        prog="kango-chrome-runner",
        description="Launch Chrome with StratosX extensions",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all registered plugins",
    )
    parser.add_argument(
        "--plugin", type=str, default="",
        help="Plugin ID(s) to launch (comma-separated)",
    )
    parser.add_argument(
        "--url", type=str, default="",
        help="Override start URL",
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="Stop all running Chrome sessions",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show status of running sessions",
    )
    parser.add_argument(
        "--clean-profile", type=str, default="",
        help="Delete a Chrome profile for fresh start",
    )
    parser.add_argument(
        "--no-icloud", action="store_true",
        help="Skip iCloud symlink setup",
    )

    args = parser.parse_args()
    runner = ChromeRunner()

    # ── List ──
    if args.list:
        print("\nRegistered plugins:")
        print("─" * 50)
        for p in runner.list_plugins():
            status = "✅" if p.enabled else "⛔"
            print(f"  {status}  {p.id:20s}  {p.name}")
            print(f"      {p.description}")
            print(f"      path: {p.path}")
            print()
        return

    # ── Stop ──
    if args.stop:
        runner.stop()
        return

    # ── Status ──
    if args.status:
        status = runner.status()
        if not status:
            print("\nNo running sessions.")
            return
        print("\nRunning sessions:")
        for s in status:
            alive = "🟢" if s["alive"] else "🔴"
            print(
                f"  {alive} {s['profile']} "
                f"(PID {s['pid']}) — "
                f"{', '.join(s['plugins'])} — "
                f"{s['uptime_min']} min"
            )
        return

    # ── Clean profile ──
    if args.clean_profile:
        runner.clean_profile(args.clean_profile)
        return

    # ── Launch specific plugin(s) ──
    if args.plugin:
        ids = [x.strip() for x in args.plugin.split(",")]
        runner.launch(
            ids,
            start_url=args.url,
            setup_icloud=not args.no_icloud,
        )
        print("\n  Chrome is running. Press Ctrl+C to stop.\n")
        try:
            import time
            while True:
                time.sleep(2)
                alive = any(
                    s["alive"] for s in runner.status()
                )
                if not alive:
                    print("\n  Chrome closed.")
                    break
        except KeyboardInterrupt:
            print("\n  Stopping...")
            runner.stop()
        return

    # ── Interactive menu (no args) ──
    interactive_menu(runner)


if __name__ == "__main__":
    main()
