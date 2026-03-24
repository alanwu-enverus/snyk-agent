import re
import subprocess
from pathlib import Path

from snyk_agent import _BaseSnykAgent

PYTHON_SYSTEM_PROMPT = """
Ecosystem: Python (Poetry)
Manifest file: pyproject.toml
Lock file: poetry.lock

Lock file regeneration:
- After updating pyproject.toml, run: run_command('poetry update <package>', project_dir)
- This regenerates poetry.lock with the new resolved version.

Transitive dependencies:
- set_dependency_version automatically handles transitive (indirect) dependencies.
  If the package is not already in pyproject.toml, it will be added as a new direct
  dependency entry to pin the resolved version (e.g. pyjwt = ">=2.10.1,<3.0.0").
- Only mark a fix as successful if set_dependency_version returned a success message
  (e.g. "Updated '...' to '...'" or "Added '...' to '...'"). Never report an errored
  fix as successful.

Post-fix validation (run after all manifest changes and the re-scan):
1. Run `run_command('poetry install', project_dir)` to ensure the lock file is
   consistent and no dependency conflicts were introduced by the fixes.
2. Determine the project's lint and test commands by reading pyproject.toml
   (look for [tool.ruff], [tool.pytest.ini_options], or [tool.scripts] sections).
   Then run:
   - Lint:  run_command('poetry run ruff check .', project_dir)
            (fall back to 'poetry run flake8 .' if ruff is not configured)
   - Tests: run_command('poetry run pytest', project_dir)
            (use any extra pytest args found in pyproject.toml, e.g. --tb=short)
   Report whether lint and tests passed or failed. If either fails, include the
   relevant error output in the summary so the user can investigate."""


def set_dependency_version(manifest_path: str, package_name: str, new_version: str) -> str:
    """Safely update a single dependency version in pyproject.toml.

    new_version e.g. "^2.12.0" or ">=2.12.0,<3.0.0"
    Supports both inline table form (package = {version = "old", ...})
    and simple string form (package = "old").
    """
    path = Path(manifest_path)
    if not path.exists():
        return f"Error: file not found: {manifest_path}"

    if path.name != "pyproject.toml":
        return f"Unsupported manifest '{path.name}'. Expected pyproject.toml."

    content = path.read_text(encoding="utf-8")
    escaped = re.escape(package_name)

    try:
        # Try inline table form first: package = {version = "old", ...}
        new_content, n = re.subn(
            rf'(?mi)^({escaped}\s*=\s*\{{[^}}]*version\s*=\s*")[^"]+(")',
            rf"\g<1>{new_version}\2",
            content,
        )
        if n == 0:
            # Fall back to simple string form: package = "old"
            new_content, n = re.subn(
                rf'(?mi)^({escaped}\s*=\s*")[^"]+(")',
                rf"\g<1>{new_version}\2",
                content,
            )
        if n == 0:
            # Package not in manifest — it's a transitive dep. Pin it by adding a direct entry.
            section_match = re.search(r"(?m)^\[tool\.poetry\.dependencies\]$", content)
            if not section_match:
                return f"Error: '[tool.poetry.dependencies]' section not found in {manifest_path}"
            # Insert before the next section header (or end of file)
            after_header = content[section_match.end():]
            next_section = re.search(r"(?m)^\[", after_header)
            insert_pos = section_match.end() + (next_section.start() if next_section else len(after_header))
            new_line = f'\n{package_name} = "{new_version}"\n'
            new_content = content[:insert_pos] + new_line + content[insert_pos:]
            path.write_text(new_content, encoding="utf-8")
            return f"Added '{package_name}' = '{new_version}' to {manifest_path}"

        path.write_text(new_content, encoding="utf-8")
        return f"Updated '{package_name}' to '{new_version}' in {manifest_path}"
    except Exception as e:
        return f"Error updating {manifest_path}: {e}"


def run_command(command: str, cwd: str) -> str:
    """Run a Poetry command in a given directory and return stdout+stderr.

    Use this to regenerate the lock file after updating pyproject.toml:
      run_command('poetry update <package>', '/path/to/project')
    Only 'poetry' commands are permitted.
    """
    if not re.match(r"^poetry\s+", command.strip()):
        return "Error: only 'poetry' commands are permitted."
    try:
        venv_activate = Path(cwd) / ".venv" / "bin" / "activate"
        shell_command = f". '{venv_activate}' && {command}" if venv_activate.exists() else command
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


def find_manifest_files(project_dir: str) -> str:
    """List Poetry manifest and lock files in the project root or src directory.

    Detects: pyproject.toml, poetry.lock
    """
    targets = {"pyproject.toml", "poetry.lock"}
    try:
        root = Path(project_dir)
        search_dirs = [root, root / "src"]
        found = [
            str(d / name)
            for d in search_dirs
            for name in sorted(targets)
            if (d / name).exists()
        ]
        return "\n".join(found) if found else "No Poetry manifest files found."
    except Exception as e:
        return f"Error reading project directory: {e}"


class PythonAgent(_BaseSnykAgent):
    _language_prompt = PYTHON_SYSTEM_PROMPT
    _agent_name = "snyk-agent-python"

    def _register_tools(self) -> None:
        self.agent.tool_plain(set_dependency_version)
        self.agent.tool_plain(run_command)
        self.agent.tool_plain(find_manifest_files)
