"""CommandRunner — the safe way ThurSec invokes external tools.

The original hackingtool runs everything through ``os.system(...)`` with
string-interpolated input: no timeout, shell injection everywhere, output lost
to the terminal. This replaces that with:

  * no shell — args are a list, so target values can't break out into commands
  * hard timeouts — a hung tool can't hang the whole run
  * captured, structured output — stdout/stderr/return code come back as data
  * a tool availability check with an install hint instead of a stack trace
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass


class ToolNotFoundError(Exception):
    def __init__(self, tool: str):
        super().__init__(
            f"Required tool {tool!r} not found on PATH. Install it and retry."
        )
        self.tool = tool


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandRunner:
    """Runs external commands without a shell, with a timeout."""

    def __init__(self, default_timeout: float = 120.0):
        self.default_timeout = default_timeout

    @staticmethod
    def available(tool: str) -> bool:
        return shutil.which(tool) is not None

    def require(self, tool: str) -> None:
        if not self.available(tool):
            raise ToolNotFoundError(tool)

    async def run(
        self,
        args: list[str],
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        if not args:
            raise ValueError("run() requires at least the program name in args.")
        self.require(args[0])
        timeout = self.default_timeout if timeout is None else timeout

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input_text.encode() if input_text else None),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return CommandResult(args, returncode=-1, stdout="", stderr="", timed_out=True)

        return CommandResult(
            args=args,
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
        )
