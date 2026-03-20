#!/usr/bin/env python3
"""
Docker Agent Runner
-------------------
Manages the lifecycle of Kali Linux Docker containers running Claude Code agents.
Each agent (executor, validator, spear) runs in an isolated container with full
Kali tooling, communicating with the host orchestrator via a shared volume.

Usage:
    # Build the agent image (once)
    python agent_runner.py build

    # Spawn a single agent
    python agent_runner.py spawn \
        --agent-type sqli-executor \
        --prompt "Attack: SQL Injection. Target: http://target.com ..." \
        --target http://target.com \
        --output-dir ./outputs/target.com

    # Monitor running agents
    python agent_runner.py monitor

    # Clean up stopped agent containers
    python agent_runner.py cleanup
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
PENTEST_DIR = REPO_ROOT / "projects" / "pentest"
IMAGE_NAME = "kali-agent"
DOCKERFILE = SCRIPT_DIR / "Dockerfile.kali-agent"

# Env vars to never pass into agent containers
ENV_BLACKLIST = {"CLAUDECODE"}


# ---------------------------------------------------------------------------
# Image management
# ---------------------------------------------------------------------------

def build_image(no_cache: bool = False) -> bool:
    """Build the kali-agent Docker image. Returns True on success."""
    cmd = ["docker", "build", "-t", IMAGE_NAME, "-f", str(DOCKERFILE), str(SCRIPT_DIR)]
    if no_cache:
        cmd.insert(2, "--no-cache")
    print(f"[agent_runner] Building {IMAGE_NAME} image ...")
    result = subprocess.run(cmd, timeout=1800)
    if result.returncode != 0:
        print(f"[agent_runner] ERROR: Image build failed (exit {result.returncode})")
        return False
    print(f"[agent_runner] Image {IMAGE_NAME} built successfully")
    return True


def image_exists() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", IMAGE_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Network auto-detection
# ---------------------------------------------------------------------------

def _is_docker_container(target: str) -> Optional[str]:
    """If target looks like a Docker container name/ID, return it. Otherwise None."""
    # Match container name patterns (no dots, no scheme)
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    # Check if hostname is a running container
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", hostname],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and "true" in result.stdout.lower():
        return hostname
    return None


def _get_container_network(container: str) -> Optional[str]:
    """Get the first non-default bridge network a container is attached to."""
    result = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", container],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    networks = result.stdout.strip().split()
    # Prefer non-default networks
    for net in networks:
        if net not in ("bridge", "host", "none"):
            return net
    return networks[0] if networks else None


def _is_localhost(target: str) -> bool:
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    return hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1")


def resolve_network(target: str) -> list[str]:
    """Returns docker run flags for network access to the target.

    Strategy:
    1. Target is a Docker container → join its network
    2. Target is localhost → add host.docker.internal mapping
    3. Target is remote → default bridge (internet access)
    """
    container = _is_docker_container(target)
    if container:
        network = _get_container_network(container)
        if network:
            print(f"[agent_runner] Target is Docker container '{container}' on network '{network}'")
            return ["--network", network]

    if _is_localhost(target):
        print(f"[agent_runner] Target is localhost — using host.docker.internal")
        return ["--add-host", "host.docker.internal:host-gateway"]

    print(f"[agent_runner] Target is remote — using default bridge network")
    return []


def rewrite_localhost_in_prompt(prompt: str) -> str:
    """Replace localhost references with host.docker.internal for Docker access."""
    prompt = re.sub(
        r'(https?://)localhost([:/\s])',
        r'\1host.docker.internal\2',
        prompt,
    )
    prompt = re.sub(
        r'(https?://)127\.0\.0\.1([:/\s])',
        r'\1host.docker.internal\2',
        prompt,
    )
    return prompt


# ---------------------------------------------------------------------------
# Agent spawning
# ---------------------------------------------------------------------------

def _build_env_flags() -> list[str]:
    """Build -e flags for docker run, passing safe env vars."""
    flags = []
    # Always pass API key — required for headless Claude Code in containers
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        flags.extend(["-e", f"ANTHROPIC_API_KEY={api_key}"])
    else:
        print("[agent_runner] ERROR: ANTHROPIC_API_KEY not set. "
              "Docker agents require an API key (login-based auth is not supported in containers). "
              "Set it with: export ANTHROPIC_API_KEY=sk-ant-...")
        raise EnvironmentError("ANTHROPIC_API_KEY is required for Docker agent containers")
    return flags


def _load_agent_definition(agent_md_path: Path) -> Optional[str]:
    """Load an agent .md file for --append-system-prompt injection."""
    if agent_md_path.exists():
        return agent_md_path.read_text()
    return None


def spawn_agent(
    agent_type: str,
    prompt: str,
    target: str,
    output_dir: str,
    model: str = "sonnet",
    timeout: Optional[int] = None,
    agent_definition: Optional[str] = None,
    extra_system_prompt: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> Optional[str]:
    """Spawn a Claude Code agent in a Kali Docker container.

    Args:
        agent_type: Identifier like 'sqli-executor', 'xss-executor', 'validator-001'
        prompt: The -p prompt to pass to Claude Code
        target: Target URL/host (for network auto-detection)
        output_dir: Host path for outputs (mounted rw at /workspace/outputs)
        model: Claude model (sonnet, opus, haiku)
        timeout: Container timeout in seconds (None = no limit)
        agent_definition: Content to inject via --append-system-prompt
        extra_system_prompt: Additional system prompt content (skills, etc.)
        engagement_id: Unique engagement identifier for container naming

    Returns:
        Container ID on success, None on failure.
    """
    if not image_exists():
        print(f"[agent_runner] Image {IMAGE_NAME} not found. Building ...")
        if not build_image():
            return None

    eid = engagement_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    container_name = f"{agent_type}-{eid}"

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "status"), exist_ok=True)

    # Network flags
    network_flags = resolve_network(target)

    # Rewrite localhost in prompt if target is local
    if _is_localhost(target):
        prompt = rewrite_localhost_in_prompt(prompt)

    # Build docker run command
    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        # Mount repo read-only, outputs read-write
        "-v", f"{REPO_ROOT}:/workspace:ro",
        "-v", f"{os.path.abspath(output_dir)}:/workspace/outputs:rw",
        *network_flags,
        *_build_env_flags(),
    ]

    # Privileged mode: required for nmap raw sockets, some exploit tools
    cmd.append("--privileged")

    # Resource limits
    cmd.extend(["--memory", "4g", "--cpus", "2"])

    # Timeout via Docker stop timeout
    if timeout:
        cmd.extend(["--stop-timeout", str(timeout)])

    cmd.append(IMAGE_NAME)

    # Claude Code flags (after image name = CMD)
    cmd.extend(["--model", model])

    # Inject agent definition + skills
    system_prompt_parts = []
    if agent_definition:
        system_prompt_parts.append(agent_definition)
    if extra_system_prompt:
        system_prompt_parts.append(extra_system_prompt)
    if system_prompt_parts:
        combined = "\n\n---\n\n".join(system_prompt_parts)
        cmd.extend(["--append-system-prompt", combined])

    cmd.extend(["-p", prompt])

    print(f"[agent_runner] Spawning {container_name} (model={model}) ...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[agent_runner] ERROR: Failed to spawn {container_name}: {result.stderr[:500]}")
        return None

    container_id = result.stdout.strip()[:12]
    print(f"[agent_runner] Container {container_name} started (ID: {container_id})")

    # Write initial status file
    status_path = os.path.join(output_dir, "status", f"{agent_type}.json")
    _write_status(status_path, "running", "init", f"Container {container_id} started")

    return container_id


def _write_status(path: str, status: str, phase: str, progress: str):
    """Write a status JSON file."""
    data = {
        "status": status,
        "phase": phase,
        "progress": progress,
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    with open(path, "w") as f:
        json.dump(data, f)


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

def get_container_status(container: str) -> dict:
    """Get container status via docker inspect."""
    result = subprocess.run(
        ["docker", "inspect", "--format",
         '{"status":"{{.State.Status}}","exit_code":{{.State.ExitCode}},'
         '"started":"{{.State.StartedAt}}","finished":"{{.State.FinishedAt}}"}',
         container],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"status": "not_found", "exit_code": -1}
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"status": "unknown", "exit_code": -1}


def get_container_logs(container: str, tail: int = 30) -> str:
    """Get recent container logs."""
    result = subprocess.run(
        ["docker", "logs", "--tail", str(tail), container],
        capture_output=True, text=True,
    )
    return result.stdout + result.stderr


def monitor_agents(
    containers: dict[str, str],
    output_dir: str,
    poll_interval: int = 15,
    timeout: int = 3600,
) -> dict[str, dict]:
    """Monitor running agent containers until all complete or timeout.

    Args:
        containers: {agent_type: container_id_or_name}
        output_dir: Host path where status files are written
        poll_interval: Seconds between polls
        timeout: Total timeout in seconds

    Returns:
        {agent_type: {"status": ..., "exit_code": ..., "duration": ...}}
    """
    start = time.time()
    results = {}
    pending = set(containers.keys())

    print(f"[agent_runner] Monitoring {len(pending)} agents (timeout={timeout}s) ...")

    while pending and (time.time() - start) < timeout:
        for agent_type in list(pending):
            container = containers[agent_type]
            status = get_container_status(container)

            if status["status"] == "exited":
                elapsed = time.time() - start
                results[agent_type] = {
                    **status,
                    "duration": round(elapsed, 1),
                }
                pending.remove(agent_type)
                emoji = "OK" if status["exit_code"] == 0 else "FAIL"
                print(f"  [{emoji}] {agent_type} exited (code={status['exit_code']}, {elapsed:.0f}s)")

            elif status["status"] == "not_found":
                results[agent_type] = {"status": "not_found", "exit_code": -1, "duration": 0}
                pending.remove(agent_type)
                print(f"  [GONE] {agent_type} container not found")

        if pending:
            # Print brief status update
            status_dir = os.path.join(output_dir, "status")
            for agent_type in pending:
                status_file = os.path.join(status_dir, f"{agent_type}.json")
                if os.path.exists(status_file):
                    try:
                        with open(status_file) as f:
                            s = json.load(f)
                        print(f"  [RUN] {agent_type}: phase={s.get('phase','?')}, "
                              f"progress={s.get('progress','?')}")
                    except (json.JSONDecodeError, OSError):
                        pass

            time.sleep(poll_interval)

    # Handle timeout
    for agent_type in pending:
        container = containers[agent_type]
        print(f"  [TIMEOUT] {agent_type} — stopping container")
        subprocess.run(["docker", "stop", container], capture_output=True, timeout=30)
        results[agent_type] = {
            "status": "timeout",
            "exit_code": -1,
            "duration": timeout,
        }

    return results


# ---------------------------------------------------------------------------
# Results collection & cleanup
# ---------------------------------------------------------------------------

def collect_results(
    containers: dict[str, str],
    output_dir: str,
    save_logs: bool = True,
) -> dict:
    """Collect results from completed agent containers.

    Args:
        containers: {agent_type: container_id_or_name}
        output_dir: Host path where outputs are stored
        save_logs: Whether to save full container logs

    Returns:
        Summary dict with findings per agent.
    """
    summary = {}
    logs_dir = os.path.join(output_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    for agent_type, container in containers.items():
        # Save container logs
        if save_logs:
            logs = get_container_logs(container, tail=5000)
            log_path = os.path.join(logs_dir, f"{agent_type}-container.log")
            with open(log_path, "w") as f:
                f.write(logs)

        # Count findings
        findings_dir = os.path.join(output_dir, "findings", agent_type)
        findings = []
        if os.path.isdir(findings_dir):
            findings = [d for d in os.listdir(findings_dir)
                        if os.path.isdir(os.path.join(findings_dir, d))]

        summary[agent_type] = {
            "findings_count": len(findings),
            "findings": findings,
            "log_path": log_path if save_logs else None,
        }

        print(f"  [{agent_type}] {len(findings)} finding(s)")

    return summary


def cleanup_containers(containers: dict[str, str], force: bool = False):
    """Remove agent containers."""
    for agent_type, container in containers.items():
        cmd = ["docker", "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container)
        subprocess.run(cmd, capture_output=True)
        print(f"  Removed {agent_type} ({container})")


# ---------------------------------------------------------------------------
# High-level orchestration helper
# ---------------------------------------------------------------------------

def load_skills_content() -> str:
    """Load skills and agent definitions for system prompt injection.

    Similar to run_xbow.py's _load_skills_and_agents_content() but
    focused on the pentest project.
    """
    content_parts = []

    # Load agent definitions
    agents_dir = PENTEST_DIR / ".claude" / "agents"
    if agents_dir.is_dir():
        for md_file in sorted(agents_dir.glob("*.md")):
            text = md_file.read_text()
            content_parts.append(f"# Agent: {md_file.stem}\n\n{text}")

    # Load AGENTS.md (passive knowledge)
    agents_md = REPO_ROOT / "AGENTS.md"
    if agents_md.exists():
        content_parts.append(agents_md.read_text())

    return "\n\n---\n\n".join(content_parts)


def run_engagement(
    target: str,
    executors: list[dict],
    output_dir: str,
    model: str = "sonnet",
    timeout: int = 3600,
    engagement_id: Optional[str] = None,
) -> dict:
    """Run a full engagement with multiple parallel executor containers.

    Args:
        target: Target URL/host
        executors: List of dicts with keys: agent_type, prompt, agent_definition (optional)
        output_dir: Host path for outputs
        model: Claude model
        timeout: Total timeout
        engagement_id: Unique ID for this engagement

    Returns:
        Engagement result dict.
    """
    eid = engagement_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    skills_content = load_skills_content()

    # Spawn all executors
    containers = {}
    for executor in executors:
        agent_type = executor["agent_type"]
        prompt = executor["prompt"]
        agent_def = executor.get("agent_definition")

        container_id = spawn_agent(
            agent_type=agent_type,
            prompt=prompt,
            target=target,
            output_dir=output_dir,
            model=model,
            agent_definition=agent_def,
            extra_system_prompt=skills_content,
            engagement_id=eid,
        )
        if container_id:
            containers[agent_type] = f"{agent_type}-{eid}"

    if not containers:
        print("[agent_runner] ERROR: No containers spawned")
        return {"status": "failed", "error": "No containers spawned"}

    # Monitor
    monitor_results = monitor_agents(containers, output_dir, timeout=timeout)

    # Collect results
    findings_summary = collect_results(containers, output_dir)

    # Cleanup
    cleanup_containers(containers)

    return {
        "engagement_id": eid,
        "target": target,
        "model": model,
        "containers": monitor_results,
        "findings": findings_summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Docker Agent Runner")
    sub = parser.add_subparsers(dest="command", required=True)

    # build
    build_cmd = sub.add_parser("build", help="Build the kali-agent Docker image")
    build_cmd.add_argument("--no-cache", action="store_true")

    # spawn
    spawn_cmd = sub.add_parser("spawn", help="Spawn a single agent container")
    spawn_cmd.add_argument("--agent-type", required=True,
                           help="Agent identifier (e.g., sqli-executor, xss-executor, spear, validator)")
    spawn_cmd.add_argument("--agent-definition", default=None,
                           help="Agent .md file to load (default: auto-detect from agent-type)")
    spawn_cmd.add_argument("--prompt", required=True)
    spawn_cmd.add_argument("--target", required=True)
    spawn_cmd.add_argument("--output-dir", required=True)
    spawn_cmd.add_argument("--model", default="sonnet")
    spawn_cmd.add_argument("--timeout", type=int, default=3600)

    # monitor
    sub.add_parser("monitor", help="List running agent containers")

    # cleanup
    cleanup_cmd = sub.add_parser("cleanup", help="Remove stopped agent containers")
    cleanup_cmd.add_argument("--force", action="store_true")

    args = parser.parse_args()

    if args.command == "build":
        success = build_image(no_cache=args.no_cache)
        sys.exit(0 if success else 1)

    elif args.command == "spawn":
        # Auto-detect agent definition from agent-type, or use explicit path
        if args.agent_definition:
            agent_md = Path(args.agent_definition)
        else:
            # Map agent-type prefixes to definition files
            agents_dir = PENTEST_DIR / ".claude" / "agents"
            if "spear" in args.agent_type:
                agent_md = agents_dir / "pentester-spear.md"
            elif "validator" in args.agent_type:
                agent_md = agents_dir / "pentester-validator.md"
            else:
                agent_md = agents_dir / "pentester-executor.md"
        agent_def = _load_agent_definition(agent_md)

        container_id = spawn_agent(
            agent_type=args.agent_type,
            prompt=args.prompt,
            target=args.target,
            output_dir=args.output_dir,
            model=args.model,
            timeout=args.timeout,
            agent_definition=agent_def,
            extra_system_prompt=load_skills_content(),
        )
        if container_id:
            print(f"Container ID: {container_id}")
        else:
            sys.exit(1)

    elif args.command == "monitor":
        # List all kali-agent containers
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"ancestor={IMAGE_NAME}",
             "--format", "table {{.Names}}\t{{.Status}}\t{{.RunningFor}}"],
            text=True,
        )

    elif args.command == "cleanup":
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"ancestor={IMAGE_NAME}",
             "--filter", "status=exited", "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        containers = {name: name for name in result.stdout.strip().split("\n") if name}
        if containers:
            cleanup_containers(containers, force=args.force)
        else:
            print("No stopped agent containers to clean up")


if __name__ == "__main__":
    main()
