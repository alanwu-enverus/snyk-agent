import json
import os
import re
import subprocess
from pathlib import Path

from snyk_agent import _BaseSnykAgent

TYPESCRIPT_SYSTEM_PROMPT = """
Ecosystem: TypeScript / Node.js (npm)
Manifest file: package.json
Lock file: package-lock.json

Sub-project discovery:
- Call find_manifest_files(project_dir) first to discover ALL package.json files,
  including sub-projects (e.g. projects/agent-chatbot/package.json).
- Scan and fix EACH package.json independently using snyk_sca_scan.
- When regenerating the lock file for a sub-project, pass its directory
  (not the root) to run_command: run_command('npm install', sub_project_dir)

Lock file regeneration:
- After updating package.json, run: run_command('npm install', <manifest_dir>)

npm conflict handling:
- If 'npm install' fails with ERESOLVE, NEVER retry with --force or --legacy-peer-deps.
- Read the error output carefully. It shows the full conflict chain:
    "Conflicting peer dependency: <X>@<vA>"
    "  peer <X>@\"<vA>\" from <T>@<vT>"   ← T is the transitive dep causing the conflict
    "    peerOptional/peer <T>@... from <P>@..."  ← P is what pulled T in
  The fix target is <T> (the transitive dep with the incompatible peer requirement).
- Determine the correct pinned version for <T>:
  * Look at the version of <X> already installed (shown as "Found: <X>@<vB>").
  * Find the version of <T> that has a peer requirement matching <vB> — usually
    the same patch series (e.g. if <X>@19.2.19 is installed and <T>@19.2.20 requires
    <X>@19.2.20, pin <T> to 19.2.19 so its peer aligns with the installed version).
- Then fix using set_dependency_version:
  * If <T> IS in dependencies/devDependencies: update it there.
  * If <T> is NOT (a true transitive dep): add it to overrides to pin the version.
- Re-run 'npm install' after the fix. If the conflict persists, read the new error
  and repeat — there may be multiple transitive deps in the chain that need pinning.

Cleanup after fixes:
- Before validation, call cleanup_overrides(manifest_path) to remove any overrides entries
  that duplicate packages already listed in dependencies or devDependencies.
  Only true transitive pins (e.g. node-forge, qs) should remain in overrides.

Validation after fixes:
- After cleanup and lock file regeneration, verify the project still works in this exact order:
  1. Ensure dependencies are installed: run_command('npm install', project_dir)
  2. Run lint: run_command('npm run lint', project_dir)
     - If lint fails, STOP. Do NOT proceed to tests.
     - Read the FULL error output, trace to the root cause, fix it, re-run npm install,
       then re-run lint. Only proceed to step 3 once lint passes cleanly.
  3. Run tests: run_command('npm test', project_dir)
     - If tests fail, read the FULL error output and trace to the root cause — do NOT
       just retry or skip. Surface-level error messages often point to a deeper version conflict.
- Skipping a lint or test failure is never acceptable. Both must pass before the fix is complete.

  Example — "NOT SUPPORTED: option missingRefs":
    Symptom: npm test prints something like:
      Error: NOT SUPPORTED: option missingRefs
        at <project>/node_modules/ajv/dist/ajv.js:...
    What it means: ajv v7+ removed the `missingRefs` option; the resolved version of ajv
      is too new for a package that still passes `missingRefs` to it.
    How to fix:
      1. Identify which direct/transitive dep requires ajv with that option.
         Look one level up in the stack trace (e.g. jest-validate, @jest/core, or a
         schema-utils package).
      2. Check which version of ajv is currently resolved:
           run_command('npm ls ajv', project_dir)
      3. Pin ajv to v6 (the last version that supported missingRefs) via overrides:
           set_dependency_version(manifest_path, 'ajv', '^6.12.6')
      4. Re-run npm install and npm test to confirm the error is gone.
    Root-cause principle: when a test/lint error mentions an unsupported option or removed
      API inside node_modules, find the package that owns that code, check the semver
      range it needs, and pin that package to the compatible range using overrides.

- Include lint and test results in the final summary."""


def set_dependency_version(
    manifest_path: str, package_name: str, new_version: str
) -> str:
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
        for section in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ):
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

        direct = set(data.get("dependencies", {})) | set(
            data.get("devDependencies", {})
        )
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
        env = {**os.environ}
        if token := os.getenv("ARTIFACTORY_TOKEN"):
            env["ARTIFACTORY_TOKEN"] = token
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            env=env,
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
    """Recursively find all package.json and package-lock.json files under project_dir.

    Skips node_modules directories. Returns one file path per line.
    Use this to discover sub-projects (e.g. projects/agent-chatbot/package.json).
    """
    try:
        root = Path(project_dir)
        found = sorted(
            str(p)
            for p in root.rglob("package*.json")
            if "node_modules" not in p.parts
            and p.name in {"package.json", "package-lock.json"}
        )
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
