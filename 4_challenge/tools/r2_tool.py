"""
Radare2 tool wrapper — provides read-only static analysis commands
for the ReAct agent. All commands are executed against the target binary.
"""

import subprocess
import os
import re


class R2Tool:
    """Execute radare2 commands against a target binary and return output."""

    _WRITE_COMMAND_RE = re.compile(
        r"(^|[;|&\n])\s*(?:"
        r"w(?:\s|$)|wa(?:\s|$)|wx(?:\s|$)|wv(?:\s|$)|wc(?:\s|$)|"
        r"we(?:\s|$)|wo(?:\s|$)|wr(?:\s|$)|wz(?:\s|$)|"
        r"oo\+|e\s+io\.cache\s*=\s*true"
        r")"
    )

    def __init__(self, binary_path: str, r2_path: str = "r2"):
        self.binary_path = os.path.abspath(binary_path)
        self.r2_path = r2_path
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
        # Verify r2 is available
        try:
            subprocess.run(
                [self.r2_path, "-v"],
                capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"r2 not available at {self.r2_path}: {e}")

    def execute(self, command: str) -> str:
        """
        Execute a radare2 command and return the output.
        
        The command is executed in a fresh r2 session with auto-analysis (aaa)
        to ensure all data is available. Only read-only commands are safe.
        
        Args:
            command: r2 command string (e.g., "iI", "afl", "pdf @ main")
            
        Returns:
            Command output as string, truncated to 4000 chars max
        """
        cmd_clean = command.strip()
        if self._WRITE_COMMAND_RE.search(cmd_clean):
            return "[BLOCKED] r2 write or write-enabling commands are not allowed in read-only mode"

        try:
            # Use -q for quiet mode, -c to pass commands
            # Chain aaa for auto-analysis before the user command
            full_cmd = f"aaa; {cmd_clean}"
            result = subprocess.run(
                [self.r2_path, "-q", "-c", full_cmd, self.binary_path],
                capture_output=True,
                timeout=30,
                text=True,
                env={**os.environ, "PATH": os.environ.get("PATH", "")}
            )
            output = result.stdout
            if result.stderr and "WARN" not in result.stderr:
                output += "\n[STDERR]\n" + result.stderr

            # Truncate excessively long output
            if len(output) > 4000:
                output = output[:3900] + "\n... [output truncated at 4000 chars]"

            return output if output.strip() else "[r2] No output (command may have failed)"
        except subprocess.TimeoutExpired:
            return "[ERROR] r2 command timed out (30s limit)"
        except Exception as e:
            return f"[ERROR] r2 execution failed: {str(e)}"
