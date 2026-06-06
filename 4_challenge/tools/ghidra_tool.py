"""
Ghidra headless tool wrapper — provides decompilation and function listing
for the ReAct agent. Uses Ghidra's analyzeHeadless with a custom decompile script.
"""

import subprocess
import os
import shutil


class GhidraTool:
    """Decompile functions and list functions using Ghidra headless analyzer."""

    def __init__(
        self,
        binary_path: str,
        ghidra_home: str = "/opt/ghidra_12.1.2_PUBLIC",
        project_dir: str = "/tmp/ghidra_react_project",
    ):
        self.binary_path = os.path.abspath(binary_path)
        self.ghidra_home = ghidra_home
        self.project_dir = project_dir
        self.project_name = "ReactProject"
        self.binary_name = os.path.basename(binary_path)
        self.query_file = os.path.join(self.project_dir, "ghidra_query.txt")
        self.output_file = os.path.join(self.project_dir, "ghidra_output.txt")
        self.env = self._build_env()

        # Find analyzeHeadless
        self.headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        if not os.path.exists(self.headless):
            raise FileNotFoundError(f"analyzeHeadless not found at {self.headless}")

        # Find the Ghidra decompile script
        self.script_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "ghidra_scripts"
        )
        self.decomp_script = "GhidraDecomp.java"
        script_path = os.path.join(self.script_dir, self.decomp_script)
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Ghidra script not found: {script_path}")

        # Import binary into Ghidra project (if not already done)
        self._ensure_project()

    def _build_env(self):
        env = os.environ.copy()
        java = shutil.which("java")
        if java:
            java_real = os.path.realpath(java)
            bin_dir = os.path.dirname(java_real)
            java_home = os.path.dirname(bin_dir)
            env.setdefault("JAVA_HOME", java_home)
        ghidra_user_home = os.path.join(self.project_dir, ".ghidra_home")
        os.makedirs(os.path.join(ghidra_user_home, ".config"), exist_ok=True)
        env["HOME"] = ghidra_user_home
        env["XDG_CONFIG_HOME"] = os.path.join(ghidra_user_home, ".config")
        return env

    def _ensure_project(self):
        """Import the binary into a Ghidra project if not already done."""
        project_file = os.path.join(self.project_dir, f"{self.project_name}.gpr")
        if os.path.exists(project_file):
            return  # Project already exists

        print(f"[Ghidra] Importing {self.binary_name} into project (this may take ~30s)...")
        os.makedirs(self.project_dir, exist_ok=True)

        cmd = [
            self.headless,
            self.project_dir,
            self.project_name,
            "-import", self.binary_path,
            "-overwrite",
            "-scriptPath", self.script_dir,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
                text=True,
                env=self.env,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Ghidra import failed (exit {result.returncode}):\n"
                    f"STDOUT: {result.stdout[-500:]}\n"
                    f"STDERR: {result.stderr[-500:]}"
                )
            print("[Ghidra] Import complete.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Ghidra import timed out (120s)")

    def _run_headless(self) -> str:
        """Run Ghidra headless with the decompile script and return output."""
        # Ensure query file exists
        if not os.path.exists(self.query_file):
            return "[ERROR] Query file not found"

        cmd = [
            self.headless,
            self.project_dir,
            self.project_name,
            "-process", self.binary_name,
            "-scriptPath", self.script_dir,
            "-noanalysis",  # Skip re-analysis (already analyzed during import)
            "-postScript", self.decomp_script,
            self.query_file,
            self.output_file,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60,
                text=True,
                env=self.env,
            )
            # Read output file
            if os.path.exists(self.output_file):
                with open(self.output_file, "r", encoding="utf-8", errors="replace") as f:
                    output = f.read()
                return output if output.strip() else "[Ghidra] No output produced"
            else:
                return (
                    f"[Ghidra] No output file generated. "
                    f"Return code: {result.returncode}\n"
                    f"STDOUT tail:\n{result.stdout[-1000:]}\n"
                    f"STDERR tail:\n{result.stderr[-1000:]}"
                )
        except subprocess.TimeoutExpired:
            return "[ERROR] Ghidra headless timed out (60s)"
        except Exception as e:
            return f"[ERROR] Ghidra execution failed: {str(e)}"

    def decompile(self, address: str) -> str:
        """
        Decompile the function containing the given address.
        
        Args:
            address: Hex address string like "0x401264"
            
        Returns:
            C-like decompiled pseudocode
        """
        # Write query
        os.makedirs(self.project_dir, exist_ok=True)
        with open(self.query_file, "w", encoding="utf-8") as f:
            f.write(address.strip())

        output = self._run_headless()

        if len(output) > 4000:
            output = output[:3900] + "\n... [output truncated at 4000 chars]"

        return output

    def list_functions(self) -> str:
        """
        List all functions identified by Ghidra.
        
        Returns:
            Newline-separated list of addresses and function names
        """
        # Write special query
        os.makedirs(self.project_dir, exist_ok=True)
        with open(self.query_file, "w", encoding="utf-8") as f:
            f.write("LIST_FUNCS")

        output = self._run_headless()

        if len(output) > 4000:
            output = output[:3900] + "\n... [output truncated at 4000 chars]"

        return output
