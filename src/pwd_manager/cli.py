import os
import signal
import subprocess
import sys
from pathlib import Path

import click

PID_FILE = Path(".pwd_manager.pid")


@click.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=5000, show_default=True, type=int)
@click.option("--workers", default=2, show_default=True, type=int)
@click.option("--threads", default=4, show_default=True, type=int)
@click.option("--timeout", default=60, show_default=True, type=int)
@click.option("--env-file", type=click.Path(exists=True, path_type=Path))
@click.option("--reload/--no-reload", default=False, show_default=True)
def start(host, port, workers, threads, timeout, env_file, reload):
    """Start the password manager webapp."""
    if env_file:
        os.environ["PWD_MANAGER_ENV_FILE"] = str(env_file)

    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "--bind",
        f"{host}:{port}",
        "--workers",
        str(workers),
        "--worker-class",
        "gthread",
        "--threads",
        str(threads),
        "--timeout",
        str(timeout),
        "--keep-alive",
        "2",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
    ]
    if reload:
        cmd.append("--reload")
    cmd.append("pwd_manager:create_app()")

    process = subprocess.Popen(cmd)
    PID_FILE.write_text(str(process.pid))

    def _shutdown(signum, _frame):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        process.wait()
    finally:
        PID_FILE.unlink(missing_ok=True)


@click.command()
@click.option(
    "--pid-file",
    default=str(PID_FILE),
    show_default=True,
    type=click.Path(path_type=Path),
)
def stop(pid_file):
    """Stop a running password manager webapp."""
    pid_path = Path(pid_file)
    if not pid_path.exists():
        click.echo("No pid file found. Is the webapp running?")
        return

    pid = int(pid_path.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        click.echo(f"Process {pid} not found.")
    else:
        click.echo(f"Stopped webapp (pid {pid}).")
    pid_path.unlink(missing_ok=True)
