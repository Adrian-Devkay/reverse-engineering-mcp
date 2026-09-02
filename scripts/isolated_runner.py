#!/usr/bin/env python3
"""Run a fixed-profile authorized sample inside a local Docker/Podman lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


MAX_ARGS = 64
MAX_ARG_LENGTH = 2048
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_REPORTED_OUTPUT_CHARS = 64_000
ALLOWED_PROFILES = {"native", "strace", "gdb-batch", "qemu-aarch64", "qemu-arm", "qemu-x86_64"}


def _load_case(case_dir: Path) -> dict[str, object]:
    manifest = case_dir / "case.json"
    if not manifest.is_file():
        raise ValueError("case.json is required; create it with init_case.py first")
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("case.json is invalid or unreadable") from exc
    if record.get("schema") != "apex-reverse-engineering/case-v1":
        raise ValueError("unsupported case schema")
    scope = record.get("scope")
    if not isinstance(scope, dict) or not str(scope.get("authorization", "")).strip():
        raise ValueError("case.json has no authorization basis")
    return record


def _resolve_artifact(case_dir: Path, case: dict[str, object], artifact_arg: str) -> tuple[Path, str]:
    candidate = Path(artifact_arg).expanduser()
    if not candidate.is_absolute():
        candidate = case_dir / candidate
    artifact = candidate.resolve(strict=True)
    if not artifact.is_file() or case_dir != artifact and case_dir not in artifact.parents:
        raise ValueError("artifact must be a regular file inside case_dir")
    manifest_artifact = case.get("artifact")
    if not isinstance(manifest_artifact, dict) or not isinstance(manifest_artifact.get("path"), str):
        raise ValueError("case.json has no artifact path")
    if Path(manifest_artifact["path"]).expanduser().resolve() != artifact:
        raise ValueError("artifact does not match the authorized case manifest")
    expected_size = manifest_artifact.get("size_bytes")
    expected_sha256 = manifest_artifact.get("sha256")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise ValueError("case.json has no valid artifact size")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("case.json has no valid artifact SHA-256")
    if artifact.stat().st_size != expected_size:
        raise ValueError("artifact size does not match the authorized case manifest")
    digest = hashlib.sha256()
    with artifact.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest().lower() != expected_sha256.lower():
        raise ValueError("artifact SHA-256 does not match the authorized case manifest")
    relative = artifact.relative_to(case_dir).as_posix()
    return artifact, relative


def _container_command(profile: str, relative_artifact: str, args: list[str]) -> list[str]:
    target = "/case/" + relative_artifact
    if profile == "native":
        return [target, *args]
    if profile == "strace":
        return ["strace", "-f", "-qq", "--", target, *args]
    if profile == "gdb-batch":
        return [
            "gdb",
            "--batch",
            "--nx",
            "--nh",
            "--eval-command",
            "set pagination off",
            "--eval-command",
            "info files",
            "--args",
            target,
            *args,
        ]
    if profile.startswith("qemu-"):
        return [profile, target, *args]
    raise ValueError("unsupported lab profile")


def build_runtime_command(runtime: str, image: str, case_dir: Path, container_command: list[str]) -> list[str]:
    if runtime not in {"docker", "podman"}:
        raise ValueError("runtime must be docker or podman")
    if "," in str(case_dir):
        raise ValueError("case_dir containing commas is not supported by the safe mount builder")
    return [
        runtime,
        "run",
        "--rm",
        "--init",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--ulimit",
        "nofile=64:64",
        "--ulimit",
        "fsize=8388608:8388608",
        "--user=65532:65532",
        "--mount",
        f"type=bind,source={case_dir},destination=/case,readonly",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--tmpfs",
        "/dev/shm:rw,noexec,nosuid,nodev,size=16m",
        "--tmpfs",
        "/output:rw,noexec,nosuid,nodev,size=64m",
        image,
        *container_command,
    ]


def redact_output(value: bytes, case_dir: Path) -> tuple[str, bool]:
    text = value.decode("utf-8", errors="replace")
    for local_value in (str(case_dir), str(case_dir.parent)):
        text = text.replace(local_value, "<redacted-path>")
    text = re.sub(r"(?i)(authorization|cookie|token|password|secret|api[_-]?key)\s*[:=]\s*(?:bearer\s+)?\S+", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)bearer\s+\S+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?<![\w.])/(?:home|root|Users|private|tmp)/[^\s\"']+", "<redacted-path>", text)
    if len(text) > MAX_REPORTED_OUTPUT_CHARS:
        return text[:MAX_REPORTED_OUTPUT_CHARS], True
    return text, False


def _child_limits(timeout_seconds: int):
    if os.name != "posix":
        return None

    def limit_resources() -> None:
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds, timeout_seconds + 1))
            resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        except (ImportError, OSError, ValueError):
            return

    return limit_resources


def _run_process(command: list[str], timeout_seconds: int, case_dir: Path, include_output: bool) -> dict[str, object]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/tmp",
        "LC_ALL": "C",
        "LANG": "C",
        "TERM": "dumb",
    }
    with tempfile.TemporaryDirectory(prefix="apex-lab-host-") as temp_dir:
        stdout_path = Path(temp_dir) / "stdout"
        stderr_path = Path(temp_dir) / "stderr"
        timed_out = False
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=environment,
                shell=False,
                start_new_session=True,
                preexec_fn=_child_limits(timeout_seconds),
            )
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
        stdout = stdout_path.read_bytes()[:MAX_OUTPUT_BYTES]
        stderr = stderr_path.read_bytes()[:MAX_OUTPUT_BYTES]
        record: dict[str, object] = {
            "returncode": process.returncode,
            "timed_out": timed_out,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "output_truncated": stdout_path.stat().st_size > MAX_OUTPUT_BYTES or stderr_path.stat().st_size > MAX_OUTPUT_BYTES,
        }
        if include_output:
            stdout_text, stdout_truncated = redact_output(stdout, case_dir)
            stderr_text, stderr_truncated = redact_output(stderr, case_dir)
            record.update(
                {
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "reported_output_truncated": stdout_truncated or stderr_truncated,
                }
            )
        return record


def run_lab(
    case_dir: Path,
    artifact_arg: str,
    runtime: str,
    image: str,
    profile: str,
    args: list[str],
    timeout_seconds: int,
    include_output: bool,
) -> dict[str, object]:
    if profile not in ALLOWED_PROFILES:
        raise ValueError("unsupported lab profile")
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    if len(args) > MAX_ARGS or any(len(item) > MAX_ARG_LENGTH for item in args):
        raise ValueError("too many or oversized target arguments")
    if any(character.isspace() for character in image) or not re.fullmatch(r".+@sha256:[0-9a-fA-F]{64}", image):
        raise ValueError("image must use a sha256 digest; tagged images are unsupported")
    if not shutil.which(runtime):
        raise ValueError("requested container runtime is unavailable")
    case_dir = case_dir.expanduser().resolve()
    if not case_dir.is_dir():
        raise ValueError("case_dir must be an existing directory")
    case = _load_case(case_dir)
    artifact, relative_artifact = _resolve_artifact(case_dir, case, artifact_arg)
    container_command = _container_command(profile, relative_artifact, args)
    command = build_runtime_command(runtime, image, case_dir, container_command)

    inspect = subprocess.run(
        [runtime, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp", "LC_ALL": "C", "LANG": "C"},
        shell=False,
        timeout=10,
        check=False,
    )
    if inspect.returncode != 0:
        raise ValueError("image is not available locally; automatic image pulls are disabled")

    started = datetime.now(timezone.utc).isoformat()
    result = _run_process(command, timeout_seconds, case_dir, include_output)
    result.update(
        {
            "schema": "apex-reverse-engineering/lab-run-v1",
            "started_utc": started,
            "ended_utc": datetime.now(timezone.utc).isoformat(),
            "runtime": runtime,
            "image": image,
            "image_pull": False,
            "profile": profile,
            "artifact": relative_artifact,
            "policy": {
                "network": "none",
                "root_filesystem": "read-only",
                "user": "65532:65532",
                "capabilities": "drop-all",
                "no_new_privileges": True,
                "memory": "512m",
                "cpus": 1,
                "pids": 64,
                "timeout_seconds": timeout_seconds,
                "image_policy": "digest-pinned-local-only",
            },
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("artifact", help="Artifact path relative to case_dir; must match case.json")
    parser.add_argument("--runtime", choices=("docker", "podman"), required=True)
    parser.add_argument("--image", required=True, help="Local image reference pinned by @sha256 digest")
    parser.add_argument("--profile", choices=sorted(ALLOWED_PROFILES), default="native")
    parser.add_argument("--arg", action="append", default=[], help="Argument passed to the target; may be repeated")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--execution-approved", action="store_true", help="Required explicit approval for sample execution")
    parser.add_argument("--include-output", action="store_true", help="Include bounded, redacted stdout/stderr; default stores hashes only")
    parser.add_argument("--report", type=Path, default=None, help="Report path inside case_dir; defaults to lab-run.json")
    args = parser.parse_args()

    if not args.execution_approved:
        parser.error("--execution-approved is required; do not execute a sample implicitly")
    try:
        result = run_lab(
            args.case_dir,
            args.artifact,
            args.runtime,
            args.image,
            args.profile,
            args.arg,
            args.timeout_seconds,
            args.include_output,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        parser.error(str(exc))

    case_dir = args.case_dir.expanduser().resolve()
    report = (case_dir / "lab-run.json") if args.report is None else args.report.expanduser().resolve()
    if case_dir != report.parent and case_dir not in report.parents:
        parser.error("report must be inside case_dir")
    if report.exists():
        parser.error(f"refusing to overwrite existing report: {report}")
    report.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
