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
2. Scan the project by passing the project root directory directly to snyk_sca_scan.
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
5. Provide a summary: what was fixed, what was skipped, what was re-scan result and any remaining issues."""


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
            env={**os.environ, "SNYK_TOKEN": os.getenv("SNYK_TOKEN", "")},
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

    async def run(self, project_dir: str) -> None:
        snyk_trust_folder(project_dir)
        print(f"\nScanning project: {project_dir}")
        print(
            "Open source scan only — fixing CRITICAL and HIGH, skipping MEDIUM and LOW...\n"
        )

        async with self.agent:
            result = await self.agent.run(
                f"Scan and fix the project at '{project_dir}'.",
                usage_limits=UsageLimits(request_limit=200),
            )

        print(result.output)
