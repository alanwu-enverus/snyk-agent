import json
import os
import re
import subprocess
from pathlib import Path

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.models.bedrock import BedrockConverseModel
from pydantic_ai.providers.bedrock import BedrockProvider

SNYK_CONFIG = Path.home() / ".config" / "configstore" / "snyk.json"


def snyk_trust_folder(project_dir: str) -> None:
    """Pre-trust the project folder in Snyk's config before MCP starts."""
    config = json.loads(SNYK_CONFIG.read_text()) if SNYK_CONFIG.exists() else {}
    trusted = config.get("TRUSTED_FOLDERS", [])
    if project_dir not in trusted:
        trusted.append(project_dir)
        config["TRUSTED_FOLDERS"] = trusted
        SNYK_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        SNYK_CONFIG.write_text(json.dumps(config))
        print(f"Trusted folder added: {project_dir}")


class SnykAgent:
    def __init__(self):
        snyk_server = MCPServerStdio(
            "snyk",
            args=["mcp", "-t", "stdio"],
            env={**os.environ, "SNYK_TOKEN": os.getenv("SNYK_TOKEN", "")},
            timeout=60,
        )
        model = BedrockConverseModel(
            model_name="anthropic.claude-3-haiku-20240307-v1:0",
            provider=BedrockProvider(region_name="us-east-1"),
        )
        self.agent = Agent(
            model=model,
            name="snyk-agent",
            toolsets=[snyk_server],
            system_prompt="""You are a security engineer using Snyk to find and fix open source dependency vulnerabilities.

Supported ecosystems:
- Python: pyproject.toml, requirements.txt, Pipfile
- Java / Kotlin: pom.xml, build.gradle, build.gradle.kts
- TypeScript / Node.js: package.json

Your task:
1. Use ONLY the Snyk open source (SCA) scanning tool — do NOT run code analysis, container,
   infrastructure-as-code, or any other scan type.
2. Scan the project by passing the project root directory directly to snyk_sca_scan.
   Snyk detects all ecosystems and manifest files automatically.
   Only use find_manifest_files if you need to identify which lock file manager is in use
   (e.g. to know whether to run 'npm install' vs 'yarn install' after a fix).
3. For each vulnerability found across all ecosystems:
   - FIX it if severity is CRITICAL or HIGH by using set_dependency_version to update
     ONLY the affected package version in the manifest file. Do NOT use write_file for
     manifest edits — it replaces the entire file and destroys all other content.
   - When choosing the safe version, ALWAYS prefer the minimum version that fixes the issue
     within the SAME major version (e.g., prefer >=3.26.2,<4.0.0 over ^4.x).
     Only bump to a new major version if no safe fix exists in the current major version series.
     This avoids breaking compatibility with other packages that pin to the current major version.
   - SKIP it if severity is MEDIUM or LOW — just note it was skipped.
   - IMPORTANT: Lock files must be regenerated after updating any manifest, because Snyk
     scans the LOCK FILE for actual resolved versions — editing only the manifest has no effect.
     * Poetry (pyproject.toml + poetry.lock): run_command('poetry update <package>', project_dir)
     * npm (package.json + package-lock.json): run_command('npm install', project_dir)
     * Yarn (package.json + yarn.lock): run_command('yarn install', project_dir)
     * pnpm (package.json + pnpm-lock.yaml): run_command('pnpm install', project_dir)
     * pip (requirements.txt): no lock file — no extra step needed.
4. After all fixes, re-scan each ecosystem to confirm critical/high issues are resolved.
5. Provide a summary grouped by ecosystem: what was fixed, what was skipped, and any remaining issues.""",
        )

        self.agent.tool_plain(self.set_dependency_version)
        self.agent.tool_plain(self.read_file)
        self.agent.tool_plain(self.write_file)
        self.agent.tool_plain(self.list_files)
        self.agent.tool_plain(self.run_command)
        self.agent.tool_plain(self.find_manifest_files)

    @staticmethod
    def set_dependency_version(
        manifest_path: str, package_name: str, new_version: str
    ) -> str:
        """Safely update a single dependency version in a manifest file.

        Only the specified package version is changed — ALL other file content is preserved.
        Use this instead of write_file for ALL manifest version bumps.

        Supports:
          - package.json   : new_version e.g. "^19.2.19"
                             Handles: dependencies, devDependencies, peerDependencies,
                             optionalDependencies, overrides, resolutions, pnpm.overrides
          - pyproject.toml : new_version e.g. "^2.12.0" or ">=2.12.0,<3.0.0"
          - requirements.txt: new_version e.g. ">=2.12.0,<3.0.0" (operator included)
        """
        import json as _json
        import re as _re

        path = Path(manifest_path)
        if not path.exists():
            return f"Error: file not found: {manifest_path}"

        content = path.read_text(encoding="utf-8")
        filename = path.name

        try:
            if filename == "package.json":
                data = _json.loads(content)
                updated = False
                # Top-level sections including overrides/resolutions (npm/Yarn/pnpm)
                for section in (
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                    "overrides",
                    "resolutions",
                ):
                    if section in data and package_name in data[section]:
                        data[section][package_name] = new_version
                        updated = True
                # pnpm stores overrides under pnpm.overrides
                pnpm = data.get("pnpm", {})
                if isinstance(pnpm, dict) and package_name in pnpm.get("overrides", {}):
                    pnpm["overrides"][package_name] = new_version
                    updated = True
                if not updated:
                    return f"Error: '{package_name}' not found in any dependency section of {manifest_path}"
                path.write_text(_json.dumps(data, indent=2) + "\n", encoding="utf-8")

            elif filename == "pyproject.toml":
                escaped = _re.escape(package_name)
                # inline table form: package = {version = "old", extras = [...]}
                new_content, n = _re.subn(
                    rf'(?mi)^({escaped}\s*=\s*\{{[^}}]*version\s*=\s*")[^"]+(")',
                    rf"\g<1>{new_version}\2",
                    content,
                )
                if n == 0:
                    # simple string form: package = "old"
                    new_content, n = _re.subn(
                        rf'(?mi)^({escaped}\s*=\s*")[^"]+(")',
                        rf"\g<1>{new_version}\2",
                        content,
                    )
                if n == 0:
                    return f"Error: '{package_name}' not found in {manifest_path}"
                path.write_text(new_content, encoding="utf-8")

            elif filename == "requirements.txt":
                escaped = _re.escape(package_name)
                new_content, n = _re.subn(
                    rf"(?mi)^{escaped}\s*(==|>=|<=|!=|~=|>|<|\^)[^\r\n]*",
                    f"{package_name}{new_version}",
                    content,
                )
                if n == 0:
                    return f"Error: '{package_name}' not found in {manifest_path}"
                path.write_text(new_content, encoding="utf-8")

            else:
                return (
                    f"Unsupported manifest '{filename}' for surgical update. "
                    "Read the file with read_file first, make targeted edits, then write back with write_file."
                )

            return f"Updated '{package_name}' to '{new_version}' in {manifest_path}"

        except Exception as e:
            return f"Error updating {manifest_path}: {e}"

    @staticmethod
    def read_file(path: str) -> str:
        """Read the contents of a file."""
        try:
            return Path(path).read_text(encoding="utf-8")
        except Exception as e:
            return f"Error reading file: {e}"

    @staticmethod
    def write_file(path: str, content: str) -> str:
        """Write content to a file, overwriting it completely."""
        try:
            Path(path).write_text(content, encoding="utf-8")
            return f"Successfully wrote {path}"
        except Exception as e:
            return f"Error writing file: {e}"

    @staticmethod
    def list_files(directory: str) -> str:
        """List files in a directory (non-recursive)."""
        try:
            entries = sorted(Path(directory).iterdir())
            return "\n".join(str(e) for e in entries)
        except Exception as e:
            return f"Error listing directory: {e}"

    @staticmethod
    def run_command(command: str, cwd: str) -> str:
        """Run a package manager command in a given directory and return stdout+stderr.

        Use this to regenerate lock files after updating manifests, e.g.:
          run_command('poetry update pyjwt', '/path/to/project')  # Python/Poetry
          run_command('npm install', '/path/to/project')          # Node.js/npm
          run_command('yarn install', '/path/to/project')         # Node.js/Yarn
          run_command('pnpm install', '/path/to/project')         # Node.js/pnpm
        Only 'poetry', 'pip', 'npm', 'yarn', and 'pnpm' commands are permitted.
        """
        # Restrict to safe package-manager commands only
        if not re.match(r"^(poetry|pip|npm|yarn|pnpm)\s+", command.strip()):
            return "Error: only 'poetry', 'pip', 'npm', 'yarn', or 'pnpm' commands are permitted."
        try:
            # Activate .venv if present so poetry/pip resolve the correct environment
            venv_activate = Path(cwd) / ".venv" / "bin" / "activate"
            if venv_activate.exists() and re.match(
                r"^(poetry|pip)\s+", command.strip()
            ):
                shell_command = f". '{venv_activate}' && {command}"
            else:
                shell_command = command
            result = subprocess.run(
                shell_command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = result.stdout + result.stderr
            return output.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            return "Error: command timed out after 120 seconds."
        except Exception as e:
            return f"Error running command: {e}"

    @staticmethod
    def find_manifest_files(project_dir: str) -> str:
        """List dependency manifests and lock files in the project root directory (non-recursive).

        Use this to identify which package manager and lock file type are present, so you
        know which regeneration command to run after updating a manifest. Checks only the
        immediate root — lock files are always at the project root.

        Detects: pyproject.toml, poetry.lock, requirements.txt, Pipfile,
                 package.json, package-lock.json, yarn.lock, pnpm-lock.yaml,
                 pom.xml, build.gradle, build.gradle.kts
        """
        targets = {
            "pyproject.toml",
            "poetry.lock",
            "requirements.txt",
            "Pipfile",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
        }
        try:
            root = Path(project_dir)
            found = [
                str(root / name) for name in sorted(targets) if (root / name).exists()
            ]
            return "\n".join(found) if found else "No manifest files found."
        except Exception as e:
            return f"Error reading project directory: {e}"

    async def run(self, project_dir: str) -> None:
        snyk_trust_folder(project_dir)
        print(f"\nScanning project: {project_dir}")
        print(
            "Open source scan only — fixing CRITICAL and HIGH, skipping MEDIUM and LOW...\n"
        )

        async with self.agent.run_mcp_servers():
            result = await self.agent.run(
                f"Run an open source dependency scan (SCA only) on the project at '{project_dir}'. "
                "Pass the project root directory directly to snyk_sca_scan — it detects all ecosystems automatically. "
                "Fix all CRITICAL and HIGH severity vulnerabilities. Skip MEDIUM and LOW. "
                f"For Poetry projects, after updating pyproject.toml run 'poetry update <package>' "
                f"in '{project_dir}' to regenerate the lock file. "
                f"For npm/Angular projects, after updating package.json run 'npm install' "
                f"in the directory containing package.json to regenerate package-lock.json. "
                f"The lock file is what Snyk actually scans."
            )

        print(result.output)
