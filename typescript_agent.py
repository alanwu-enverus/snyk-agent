import json
import re
import subprocess
from pathlib import Path

from snyk_agent import _BaseSnykAgent

TYPESCRIPT_SYSTEM_PROMPT = """
Ecosystem: TypeScript / Node.js (npm)
Manifest file: package.json
Lock file: package-lock.json

Lock file regeneration:
- After updating package.json, run: run_command('npm install', project_dir)

npm conflict handling:
- If 'npm install' fails with a peer dependency conflict, NEVER retry with --force.
- Instead, identify the conflicting package from the error output:
  * If it IS in dependencies/devDependencies: update it there with set_dependency_version.
  * If it is NOT (a transitive dep): pin it via overrides with set_dependency_version —
    this forces the version for packages you don't own directly.
- Re-run 'npm install' after the fix.

Cleanup after fixes:
- Before validation, call cleanup_overrides(manifest_path) to remove any overrides entries
  that duplicate packages already listed in dependencies or devDependencies.
  Only true transitive pins (e.g. node-forge, qs) should remain in overrides.

Validation after fixes:
- After cleanup and lock file regeneration, verify the project still works:
  1. Run lint:  run_command('npm run lint', project_dir)
  2. Run tests: run_command('npm test', project_dir)
- If lint or tests fail, read the error output and fix the root cause before finishing.
- Include lint and test results in the final summary."""


def set_dependency_version(manifest_path: str, package_name: str, new_version: str) -> str:
    """Safely update a single dependency version in package.json.

    new_version e.g. "^19.2.19"
    Handles: dependencies, devDependencies, peerDependencies, optionalDependencies, overrides.
    If the package is not found in any section, adds it to overrides to pin the transitive dep.
    """
    path = Path(manifest_path)
    if not path.exists():
        return f"Error: file not found: {manifest_path}"

    if path.name != "package.json":
        return f"Unsupported manifest '{path.name}'. Expected package.json."

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        updated_direct = False
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if section in data and package_name in data[section]:
                data[section][package_name] = new_version
                updated_direct = True

        if updated_direct:
            # Remove any stale overrides entry — direct dep version is the source of truth.
            if "overrides" in data and package_name in data["overrides"]:
                del data["overrides"][package_name]
        elif "overrides" in data and package_name in data["overrides"]:
            # Already pinned in overrides — just update it.
            data["overrides"][package_name] = new_version
        else:
            # Package not found anywhere — add to overrides to pin the transitive dep.
            if "overrides" not in data:
                data["overrides"] = {}
            data["overrides"][package_name] = new_version

        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return f"Updated '{package_name}' to '{new_version}' in {manifest_path}"
    except Exception as e:
        return f"Error updating {manifest_path}: {e}"


def cleanup_overrides(manifest_path: str) -> str:
    """Remove overrides entries that duplicate packages already in dependencies or devDependencies.

    Call this after all dependency fixes are complete. Only true transitive pins
    (packages not listed as direct dependencies) should remain in overrides.
    """
    path = Path(manifest_path)
    if not path.exists():
        return f"Error: file not found: {manifest_path}"
    if path.name != "package.json":
        return f"Unsupported manifest '{path.name}'. Expected package.json."

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        overrides = data.get("overrides", {})
        if not overrides:
            return "No overrides section found — nothing to clean up."

        direct = set(data.get("dependencies", {})) | set(data.get("devDependencies", {}))
        stale = [pkg for pkg in overrides if pkg in direct]
        for pkg in stale:
            del data["overrides"][pkg]

        if not data["overrides"]:
            del data["overrides"]

        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        if stale:
            return f"Removed stale overrides: {', '.join(stale)}"
        return "No stale overrides found — overrides section is clean."
    except Exception as e:
        return f"Error cleaning up overrides: {e}"


def run_command(command: str, cwd: str) -> str:
    """Run an npm command in a given directory and return stdout+stderr.

    Use this to regenerate the lock file or validate the project:
      run_command('npm install', '/path/to/project')
      run_command('npm run lint', '/path/to/project')
      run_command('npm test', '/path/to/project')
    Only 'npm' commands are permitted.
    """
    if not re.match(r"^npm\s+", command.strip()):
        return "Error: only 'npm' commands are permitted."
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout + result.stderr
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 300 seconds."
    except Exception as e:
        return f"Error running command: {e}"


def find_manifest_files(project_dir: str) -> str:
    """List npm manifest and lock files in the project root directory (non-recursive).

    Detects: package.json, package-lock.json
    """
    targets = {"package.json", "package-lock.json"}
    try:
        root = Path(project_dir)
        found = [
            str(root / name) for name in sorted(targets) if (root / name).exists()
        ]
        return "\n".join(found) if found else "No npm manifest files found."
    except Exception as e:
        return f"Error reading project directory: {e}"


class TypeScriptAgent(_BaseSnykAgent):
    _language_prompt = TYPESCRIPT_SYSTEM_PROMPT
    _agent_name = "snyk-agent-typescript"

    def _register_tools(self) -> None:
        self.agent.tool_plain(set_dependency_version)
        self.agent.tool_plain(cleanup_overrides)
        self.agent.tool_plain(run_command)
        self.agent.tool_plain(find_manifest_files)
