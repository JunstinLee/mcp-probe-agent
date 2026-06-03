import subprocess
from pathlib import Path


class SandboxDriver:
    """封装轻量进程沙箱生命周期管理（无 Docker）。"""

    def __init__(self, sandbox_dir: Path = Path("/tmp/mcp_sandbox_secure")):
        self.sandbox_dir = sandbox_dir

    def start(self, port: int = 8766, network: bool = False) -> subprocess.Popen:
        cmd = ["python", str(self.sandbox_dir / "src" / "probe_server_secure.py")]
        if not network:
            # 使用 unshare 断网启动
            cmd = [
                "unshare", "--net", "--pid", "--fork", "--mount-proc",
            ] + cmd
        env = {
            "MCP_SANDBOX": str(self.sandbox_dir),
            "MCP_PORT": str(port),
            "PATH": "/usr/bin:/bin",
        }
        return subprocess.Popen(
            cmd,
            env=env,
            cwd=str(self.sandbox_dir),
        )

    def stop(self, proc: subprocess.Popen) -> None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
