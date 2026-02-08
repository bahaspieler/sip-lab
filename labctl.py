#!/usr/bin/env python3
"""
labctl.py -- Controller for the Docker-based SIP lab.

Orchestrates SIPp containers (UAC/UAS), Kamailio proxies, and a
tcpdump capture container.  Supports both a simple two-party call
(run_basic) and a generic scenario runner that reads scenario.json
from each scenario directory.

Workflow: compose up -> tcpdump -> UAS -> UAC -> cleanup -> compose down
Captures are written to ./captures/ via a volume mount on the capture container.
Ctrl+C triggers graceful cleanup (stop tcpdump + SIPp, then compose down).

Container name conventions: sipp_uac, sipp_uas, capture.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

# Container names (docker-compose.yml uses fixed container_name)
UAC = "sipp_uac"
UAS = "sipp_uas"
CAPTURE = "capture"

_STOP_REQUESTED = False


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def run(cmd: List[str], check: bool = True, capture_output: bool = False, text: bool = True) -> subprocess.CompletedProcess:
    """Run a command locally."""
    if os.environ.get("LABCTL_DEBUG") == "1":
        eprint("[labctl] $", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text)


def compose_base(compose_file: str, project: Optional[str]) -> List[str]:
    cmd = ["docker", "compose", "-f", compose_file]
    if project:
        cmd += ["-p", project]
    return cmd


def compose_up(compose_file: str, project: Optional[str]) -> None:
    run(compose_base(compose_file, project) + ["up", "-d"], check=True)


def compose_down(compose_file: str, project: Optional[str]) -> None:
    run(compose_base(compose_file, project) + ["down"], check=False)


def compose_ps(compose_file: str, project: Optional[str]) -> None:
    run(compose_base(compose_file, project) + ["ps"], check=False)


def compose_logs(compose_file: str, project: Optional[str], service: Optional[str], tail: int) -> None:
    cmd = compose_base(compose_file, project) + ["logs", "--tail", str(tail)]
    if service:
        cmd.append(service)
    run(cmd, check=False)


def docker_exec(container: str, args: List[str], detach: bool = False, check: bool = True,
               capture_output: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec"]
    if detach:
        cmd.append("-d")
    cmd += [container] + args
    return run(cmd, check=check, capture_output=capture_output)


def _sigint_handler(sig, frame):
    global _STOP_REQUESTED
    _STOP_REQUESTED = True
    eprint("\n[labctl] Ctrl+C received: stopping…")


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _wait_container_running(name: str, timeout_s: int = 15) -> None:
    """Wait until `docker inspect` says the container is running."""
    start = time.time()
    while True:
        cp = run(["docker", "inspect", "-f", "{{.State.Running}}", name], check=False, capture_output=True)
        if cp.returncode == 0 and cp.stdout.strip() == "true":
            return
        if time.time() - start > timeout_s:
            raise RuntimeError(f"Container '{name}' did not reach running state within {timeout_s}s")
        time.sleep(0.3)


def _start_tcpdump(pcap_in_container: str) -> None:
    # -U flushes packets to file continuously; useful if you stop early
    cmd = [
        "sh", "-lc",
        f"rm -f /tmp/tcpdump.pid; "
        f"tcpdump -i any -U -w {pcap_in_container} udp port 5060 >/tmp/tcpdump.log 2>&1 & "
        f"echo $! > /tmp/tcpdump.pid; "
        f"sleep 0.2; cat /tmp/tcpdump.pid"
    ]
    cp = docker_exec(CAPTURE, cmd, detach=False, check=True, capture_output=True)
    eprint(f"[labctl] tcpdump started (PID {cp.stdout.strip()})")


def _start_uas(scenario_file: Optional[str] = None, delay_ms: Optional[int] = None) -> None:
    """Start SIPp UAS in background.

    If scenario_file is given, use ``-sf``; otherwise the built-in ``-sn uas``.
    delay_ms sets the ``-d`` flag (used by ``<pause/>`` in custom scenarios).
    Do NOT use SIPp's ``-bg`` flag — it forks and ``$!`` would capture the dead
    parent PID instead of the real child.  Shell ``&`` keeps the real PID.
    """
    if scenario_file:
        sipp_cmd = f"sipp -sf {scenario_file} -p 5060 -m 1"
        if delay_ms is not None:
            sipp_cmd += f" -d {delay_ms}"
    else:
        sipp_cmd = "sipp -sn uas -p 5060 -m 1"
    cmd = [
        "sh", "-lc",
        f"rm -f /tmp/uas.pid; "
        f"{sipp_cmd} >/tmp/uas.log 2>&1 & "
        f"echo $! > /tmp/uas.pid; "
        f"sleep 0.2; cat /tmp/uas.pid"
    ]
    cp = docker_exec(UAS, cmd, detach=False, check=True, capture_output=True)
    eprint(f"[labctl] SIPp UAS started (PID {cp.stdout.strip()})")


def _run_uac(target: str, calls: int, delay_ms: int, verbose: bool,
             scenario_file: Optional[str] = None,
             rsa: Optional[str] = None) -> int:
    """Run SIPp UAC in foreground so the script blocks until the call finishes.

    If scenario_file is given, use ``-sf``; otherwise the built-in ``-sn uac``.
    rsa sets the ``-rsa`` flag (outbound proxy address, e.g. "proxy:5060").
    """
    if scenario_file:
        opts = ["-sf", scenario_file, "-m", str(calls), "-d", str(delay_ms)]
    else:
        opts = ["-sn", "uac", "-m", str(calls), "-d", str(delay_ms)]
    if rsa:
        opts += ["-rsa", rsa]
    if verbose:
        opts.append("-trace_msg")
    cmd_str = f"sipp {target} " + " ".join(opts)
    eprint(f"[labctl] Running UAC: {cmd_str}")
    cp = docker_exec(UAC, ["sh", "-lc", cmd_str], detach=False, check=False)
    return cp.returncode


def _kill_pidfile(container: str, pidfile: str, name: str) -> None:
    docker_exec(container, ["sh", "-lc", f"if [ -f {pidfile} ]; then kill -TERM $(cat {pidfile}) 2>/dev/null || true; fi"], check=False)
    # Give it a moment, then force-kill if still alive
    docker_exec(container, ["sh", "-lc", f"sleep 0.2; if [ -f {pidfile} ] && kill -0 $(cat {pidfile}) 2>/dev/null; then kill -KILL $(cat {pidfile}) 2>/dev/null || true; fi"], check=False)
    eprint(f"[labctl] Stopped {name} (pidfile {pidfile})")


def run_basic_workflow(compose_file: str, project: Optional[str], pcap_name: str, keep: bool,
                       calls: int, delay_ms: int, verbose: bool,
                       bye_from: str = "caller") -> int:
    """
    Basic flow:
      up -> tcpdump -> uas -> uac -> stop uas/tcpdump -> (down unless keep)

    bye_from: "caller" — UAC sends BYE (default, uses built-in SIPp scenarios)
              "callee" — UAS sends BYE (uses custom XML scenarios in /sipp/)
    """
    captures_dir = Path("captures")
    _ensure_dir(captures_dir)

    # We always write to /captures/<pcap_name> inside CAPTURE container, which maps to ./captures/<pcap_name>
    pcap_host = captures_dir / pcap_name
    pcap_in_container = f"/captures/{pcap_name}"

    rc = 1
    try:
        compose_up(compose_file, project)
        _wait_container_running(CAPTURE)
        _wait_container_running(UAS)
        _wait_container_running(UAC)

        # Start capture first
        _start_tcpdump(pcap_in_container)
        time.sleep(0.3)

        if bye_from == "callee":
            # Callee (UAS) hangs up: UAS pauses then sends BYE, UAC waits for it
            eprint(f"[labctl] Mode: callee (UAS) sends BYE after {delay_ms}ms")
            _start_uas(scenario_file="/sipp/uas_callee_bye.xml", delay_ms=delay_ms)
            time.sleep(0.3)
            rc = _run_uac(f"{UAS}:5060", calls=calls, delay_ms=delay_ms,
                          verbose=verbose, scenario_file="/sipp/uac_callee_bye.xml")
        else:
            # Caller (UAC) hangs up: default SIPp built-in behavior
            eprint(f"[labctl] Mode: caller (UAC) sends BYE after {delay_ms}ms")
            _start_uas()
            time.sleep(0.3)
            rc = _run_uac(f"{UAS}:5060", calls=calls, delay_ms=delay_ms, verbose=verbose)

        # Buffer so final packets (BYE + 200) flush through tcpdump and the
        # Docker Desktop volume mount syncs the pcap to the host filesystem.
        time.sleep(1.0)

    except Exception as ex:
        eprint(f"[labctl] ERROR: {ex}")
        rc = 2

    finally:
        # Stop background processes even on Ctrl+C or errors
        try:
            _kill_pidfile(CAPTURE, "/tmp/tcpdump.pid", "tcpdump")
        except Exception:
            pass
        try:
            _kill_pidfile(UAS, "/tmp/uas.pid", "SIPp UAS")
        except Exception:
            pass

        # Let Docker Desktop volume mount sync the pcap to the host
        time.sleep(0.5)

        if not keep:
            compose_down(compose_file, project)

        # sanity check capture
        try:
            if pcap_host.exists():
                sz = pcap_host.stat().st_size
                if sz < 200:
                    eprint(f"[labctl] WARNING: pcap looks too small ({sz} bytes): {pcap_host}")
                    eprint("[labctl] Tip: ensure UAC ran, and tcpdump captured on the correct network.")
                else:
                    eprint(f"[labctl] pcap saved: {pcap_host} ({sz} bytes)")
            else:
                eprint(f"[labctl] WARNING: pcap not found on host: {pcap_host}")
        except Exception:
            pass

    return rc


def run_scenario_workflow(scenario_dir: str, project: Optional[str], pcap_name: str,
                          keep: bool, calls: Optional[int], delay_ms: Optional[int],
                          verbose: bool) -> int:
    """Generic scenario runner.  Reads scenario.json from *scenario_dir*."""
    scenario_path = Path(scenario_dir)
    compose_file = str(scenario_path / "docker-compose.yml")
    config_path = scenario_path / "scenario.json"

    if not config_path.exists():
        eprint(f"[labctl] ERROR: {config_path} not found")
        return 2

    with open(config_path) as f:
        cfg = json.load(f)

    uac_target = cfg.get("uac_target", "sipp_uas:5060")
    uac_rsa = cfg.get("uac_rsa")        # None → no outbound proxy
    uac_scenario = cfg.get("uac_scenario")
    uas_scenario = cfg.get("uas_scenario")
    wait_for = cfg.get("wait_for", [])
    s_delay = delay_ms if delay_ms is not None else cfg.get("delay_ms", 2000)
    s_calls = calls if calls is not None else cfg.get("calls", 1)

    captures_dir = Path("captures")
    _ensure_dir(captures_dir)
    pcap_host = captures_dir / pcap_name
    pcap_in_container = f"/captures/{pcap_name}"

    rc = 1
    try:
        compose_up(compose_file, project)
        _wait_container_running(CAPTURE)
        _wait_container_running(UAS)
        _wait_container_running(UAC)
        for cname in wait_for:
            _wait_container_running(cname, timeout_s=30)

        # Extra pause for Kamailio to finish initialising
        if wait_for:
            time.sleep(1.0)

        _start_tcpdump(pcap_in_container)
        time.sleep(0.3)

        _start_uas(scenario_file=uas_scenario)
        time.sleep(0.3)

        rc = _run_uac(uac_target, calls=s_calls, delay_ms=s_delay,
                       verbose=verbose, scenario_file=uac_scenario,
                       rsa=uac_rsa)

        if rc != 0:
            eprint(f"[labctl] SIPp UAC exited with code {rc} "
                   "(may be OK — stateless proxies can cause late provisionals)")

        time.sleep(1.0)

    except Exception as ex:
        eprint(f"[labctl] ERROR: {ex}")
        rc = 2

    finally:
        try:
            _kill_pidfile(CAPTURE, "/tmp/tcpdump.pid", "tcpdump")
        except Exception:
            pass
        try:
            _kill_pidfile(UAS, "/tmp/uas.pid", "SIPp UAS")
        except Exception:
            pass
        time.sleep(0.5)
        if not keep:
            compose_down(compose_file, project)
        try:
            if pcap_host.exists():
                sz = pcap_host.stat().st_size
                if sz < 200:
                    eprint(f"[labctl] WARNING: pcap looks too small ({sz} bytes): {pcap_host}")
                else:
                    eprint(f"[labctl] pcap saved: {pcap_host} ({sz} bytes)")
            else:
                eprint(f"[labctl] WARNING: pcap not found on host: {pcap_host}")
        except Exception:
            pass

    return rc


def list_scenarios() -> None:
    """Print available scenarios under ./scenarios/."""
    scenarios_dir = Path("scenarios")
    if not scenarios_dir.exists():
        eprint("[labctl] No scenarios/ directory found")
        return
    for d in sorted(scenarios_dir.iterdir()):
        if d.is_dir() and (d / "docker-compose.yml").exists():
            has_json = "✓" if (d / "scenario.json").exists() else "✗"
            print(f"  {d.name}  [scenario.json: {has_json}]")


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="labctl.py", description="SIP lab controller")
    p.add_argument("-f", "--compose-file", default="docker-compose.yml", help="docker-compose.yml path")
    p.add_argument("-p", "--project", default=None, help="Compose project name (-p). Optional.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("up", help="docker compose up -d")
    sub.add_parser("down", help="docker compose down")
    sub.add_parser("ps", help="docker compose ps")

    logs = sub.add_parser("logs", help="docker compose logs")
    logs.add_argument("--service", default=None)
    logs.add_argument("--tail", type=int, default=200)

    ex = sub.add_parser("exec", help="docker exec into a container")
    ex.add_argument("container", help="Container name (e.g., capture, sipp_uas, sipp_uac)")
    ex.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="Command to run, e.g. -- bash -lc 'ls'")

    sub.add_parser("list", help="List available scenarios")

    run_s = sub.add_parser("run", help="Run a scenario by name (from scenarios/ dir)")
    run_s.add_argument("scenario", help="Scenario folder name, e.g. 02_proxy_stateless")
    run_s.add_argument("--pcap", default=None, help="PCAP filename (default: <scenario>.pcap)")
    run_s.add_argument("--keep", action="store_true", help="Keep containers up")
    run_s.add_argument("--calls", type=int, default=None, help="Override number of calls")
    run_s.add_argument("--delay-ms", type=int, default=None, help="Override call duration (ms)")
    run_s.add_argument("--verbose", action="store_true", help="Verbose SIPp output")

    basic = sub.add_parser("run_basic", help="Run basic SIPp UAC->UAS call and capture a pcap")
    basic.add_argument("--pcap", default="basic.pcap", help="PCAP filename under ./captures/")
    basic.add_argument("--keep", action="store_true", help="Keep containers up (do not compose down)")
    basic.add_argument("--calls", type=int, default=1, help="Number of calls (-m) to generate")
    basic.add_argument("--delay-ms", type=int, default=4000, help="Call duration in ms (-d)")
    basic.add_argument("--verbose", action="store_true", help="Run UAC with -v (more logs)")
    basic.add_argument("--bye-from", choices=["caller", "callee"], default="caller",
                       help="Who sends BYE: caller (UAC, default) or callee (UAS)")

    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    signal.signal(signal.SIGINT, _sigint_handler)

    args = parse_args(argv)
    compose_file = args.compose_file
    project = args.project

    if args.cmd == "up":
        compose_up(compose_file, project)
        return 0
    if args.cmd == "down":
        compose_down(compose_file, project)
        return 0
    if args.cmd == "ps":
        compose_ps(compose_file, project)
        return 0
    if args.cmd == "logs":
        compose_logs(compose_file, project, args.service, args.tail)
        return 0
    if args.cmd == "exec":
        if not args.exec_cmd:
            eprint("[labctl] Nothing to execute. Example: labctl.py exec capture -- bash -lc 'ip a'")
            return 2
        if args.exec_cmd and args.exec_cmd[0] == "--":
            exec_cmd = args.exec_cmd[1:]
        else:
            exec_cmd = args.exec_cmd
        cp = docker_exec(args.container, exec_cmd, detach=False, check=False)
        return cp.returncode
    if args.cmd == "list":
        list_scenarios()
        return 0
    if args.cmd == "run":
        scenario_dir = str(Path("scenarios") / args.scenario)
        if not Path(scenario_dir).exists():
            eprint(f"[labctl] Scenario not found: {scenario_dir}")
            return 2
        pcap_name = args.pcap or f"{args.scenario}.pcap"
        return run_scenario_workflow(
            scenario_dir=scenario_dir,
            project=project,
            pcap_name=pcap_name,
            keep=args.keep,
            calls=args.calls,
            delay_ms=args.delay_ms,
            verbose=args.verbose,
        )
    if args.cmd == "run_basic":
        return run_basic_workflow(
            compose_file=compose_file,
            project=project,
            pcap_name=args.pcap,
            keep=args.keep,
            calls=args.calls,
            delay_ms=args.delay_ms,
            verbose=args.verbose,
            bye_from=args.bye_from,
        )

    eprint(f"[labctl] Unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
