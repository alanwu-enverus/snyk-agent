import re
from pathlib import Path

from snyk_agent import COMMON_SYSTEM_PROMPT, _BaseSnykAgent

JAVA_SYSTEM_PROMPT = """
Ecosystem: Java / Kotlin (Gradle)
Manifest files: build.gradle or build.gradle.kts

Lock file regeneration:
- Gradle does not use a lock file — no extra step needed after updating the manifest.
- For transitive dependencies not listed directly, pin them via resolutionStrategy.force in
  the manifest using set_dependency_version."""


def set_dependency_version(manifest_path: str, package_name: str, new_version: str) -> str:
    """Safely update a single dependency version in a Gradle manifest file.

    Supports build.gradle and build.gradle.kts.
    new_version e.g. "30.1-jre"
    For transitive deps, pins via resolutionStrategy.force.
    """
    path = Path(manifest_path)
    if not path.exists():
        return f"Error: file not found: {manifest_path}"

    filename = path.name
    if filename not in ("build.gradle", "build.gradle.kts"):
        return f"Unsupported manifest '{filename}'. Expected build.gradle or build.gradle.kts."

    content = path.read_text(encoding="utf-8")
    escaped = re.escape(package_name)

    try:
        # Matches direct deps and existing force() entries: 'group:artifact:oldVersion'
        new_content, n = re.subn(
            rf"(['\"]){escaped}:[^'\"]+(['\"])",
            rf"\g<1>{package_name}:{new_version}\2",
            content,
        )
        if n == 0:
            # Transitive dep — pin it via resolutionStrategy.force
            new_content = (
                content.rstrip()
                + '\n\nconfigurations.all {\n'
                + f'    resolutionStrategy.force("{package_name}:{new_version}")\n'
                + '}\n'
            )

        path.write_text(new_content, encoding="utf-8")
        return f"Updated '{package_name}' to '{new_version}' in {manifest_path}"
    except Exception as e:
        return f"Error updating {manifest_path}: {e}"


def find_manifest_files(project_dir: str) -> str:
    """List Gradle manifest files in the project root directory (non-recursive).

    Detects: build.gradle, build.gradle.kts
    """
    targets = {"build.gradle", "build.gradle.kts"}
    try:
        root = Path(project_dir)
        found = [
            str(root / name) for name in sorted(targets) if (root / name).exists()
        ]
        return "\n".join(found) if found else "No Gradle manifest files found."
    except Exception as e:
        return f"Error reading project directory: {e}"


class JavaAgent(_BaseSnykAgent):
    _language_prompt = JAVA_SYSTEM_PROMPT
    _agent_name = "snyk-agent-java"

    def _register_tools(self) -> None:
        self.agent.tool_plain(set_dependency_version)
        self.agent.tool_plain(find_manifest_files)
