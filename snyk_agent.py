import json
import os
from pathlib import Path

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.models.bedrock import BedrockConverseModel
from pydantic_ai.providers.bedrock import BedrockProvider
from pydantic_ai.usage import UsageLimits

SNYK_CONFIG = Path.home() / ".config" / "configstore" / "snyk.json"

COMMON_SYSTEM_PROMPT = """You are a security engineer using Snyk to find and fix open source dependency vulnerabilities.

Your task:
1. Use ONLY the Snyk open source (SCA) scanning tool — do NOT run code analysis, container,
   infrastructure-as-code, or any other scan type.
2. Scan the project by calling snyk_sca_scan with the path and any scan options provided in the
   user message (e.g. all_projects, detection_depth, dev). Pass them as-is to the tool.
3. For each vulnerability found:
   - FIX it if severity is CRITICAL or HIGH by using set_dependency_version to update
     ONLY the affected package version in the manifest file.
   - When choosing the safe version, ALWAYS prefer the minimum version that fixes the issue
     within the SAME major version (e.g., prefer >=3.26.2,<4.0.0 over ^4.x).
     Only bump to a new major version if no safe fix exists in the current major version series.
     This avoids breaking compatibility with other packages that pin to the current major version.
   - SKIP it if severity is MEDIUM or LOW — just note it was skipped.
   - IMPORTANT: Lock files must be regenerated after updating any manifest, because Snyk
     scans the LOCK FILE for actual resolved versions — editing only the manifest has no effect.
4. After all fixes, re-scan the project to confirm critical/high issues are resolved.
5. Provide a summary: what was fixed, what was skipped, re-scan result, and any remaining issues.

IMPORTANT: When reporting scan results, be concise. List only: package name, installed version,
fix version, and severity. Do NOT reproduce full vulnerability descriptions or raw JSON."""

_SCAN_PROMPT_SUFFIX = (
    " Return ONLY a concise table of CRITICAL and HIGH vulnerabilities: "
    "package name | installed version | fix version | severity. "
    "If there are none, say 'No CRITICAL or HIGH vulnerabilities found.'"
)

_FIX_PROMPT_TEMPLATE = """\
Fix the following CRITICAL and HIGH vulnerabilities in '{project_dir}'.

{vuln_summary}

For each vulnerability: use set_dependency_version to update the manifest, then regenerate \
the lock file. MEDIUM and LOW issues should be skipped.
When done, report what was fixed and what (if anything) could not be fixed.\
"""

_VERIFY_PROMPT_TEMPLATE = (
    "Re-scan the project at '{project_dir}'{options_str} to verify all CRITICAL and HIGH "
    "vulnerabilities have been resolved. Report the result."
)


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


def read_file(path: str) -> str:
    """Read the contents of a file."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception as e:
        return f"Error reading file: {e}"


def list_files(directory: str) -> str:
    """List files in a directory (non-recursive)."""
    try:
        entries = sorted(Path(directory).iterdir())
        return "\n".join(str(e) for e in entries)
    except Exception as e:
        return f"Error listing directory: {e}"


class _BaseSnykAgent:
    _language_prompt: str = ""
    _agent_name: str = "snyk-agent"

    def __init__(self):
        snyk_server = MCPServerStdio(
            "snyk",
            args=["mcp", "-t", "stdio"],
            env={
                **os.environ,
                "SNYK_TOKEN": os.getenv("SNYK_TOKEN", ""),
                "ARTIFACTORY_TOKEN": os.getenv("ARTIFACTORY_TOKEN", ""),
            },
            timeout=60,
        )
        model = BedrockConverseModel(
            model_name="us.anthropic.claude-sonnet-4-6",
            provider=BedrockProvider(region_name="us-east-1"),
        )
        self.agent = Agent(
            model=model,
            name=self._agent_name,
            toolsets=[snyk_server],
            system_prompt=COMMON_SYSTEM_PROMPT + self._language_prompt,
        )
        self.agent.tool_plain(read_file)
        self.agent.tool_plain(list_files)
        self._register_tools()

    def _register_tools(self) -> None:
        """Subclasses register their language-specific tools here."""
        pass

    async def run(
        self,
        project_dir: str,
        all_projects: bool = False,
        detection_depth: int | None = None,
        dev: bool = False,
    ) -> None:
        snyk_trust_folder(project_dir)
        print(f"\nScanning project: {project_dir}")
        print(
            "Open source scan only — fixing CRITICAL and HIGH, skipping MEDIUM and LOW...\n"
        )

        options: dict = {}
        if all_projects:
            options["all_projects"] = True
        if detection_depth is not None:
            options["detection_depth"] = detection_depth
        if dev:
            options["dev"] = True

        options_str = (
            " using scan options: " + ", ".join(f"{k}={v}" for k, v in options.items())
            if options
            else ""
        )

        # Phase 1: Scan — ask for a compact summary to keep context small.
        scan_prompt = (
            f"Scan the project at '{project_dir}'{options_str}."
            + _SCAN_PROMPT_SUFFIX
        )
        async with self.agent:
            scan_result = await self.agent.run(
                scan_prompt,
                usage_limits=UsageLimits(request_limit=20),
            )

        vuln_summary = scan_result.output
        print(f"[Scan complete]\n{vuln_summary}\n")

        if "no critical or high" in vuln_summary.lower():
            print("No CRITICAL or HIGH vulnerabilities — nothing to fix.")
            return

        # Phase 2: Fix — fresh context; pass only the compact summary, not the full history.
        fix_prompt = _FIX_PROMPT_TEMPLATE.format(
            project_dir=project_dir,
            vuln_summary=vuln_summary,
        )
        async with self.agent:
            fix_result = await self.agent.run(
                fix_prompt,
                usage_limits=UsageLimits(request_limit=150),
            )

        print(f"[Fix complete]\n{fix_result.output}\n")

        # Phase 3: Verify — fresh context to confirm fixes.
        verify_prompt = _VERIFY_PROMPT_TEMPLATE.format(
            project_dir=project_dir,
            options_str=options_str,
        )
        async with self.agent:
            verify_result = await self.agent.run(
                verify_prompt,
                usage_limits=UsageLimits(request_limit=200),
            )

        print(f"[Verify complete]\n{verify_result.output}")
