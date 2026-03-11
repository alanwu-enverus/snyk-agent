import asyncio
import json
import os
import sys
import logfire
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio
from dotenv import load_dotenv
from pydantic_ai.models.bedrock import BedrockConverseModel

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

logfire.configure()  
logfire.instrument_pydantic_ai() 
load_dotenv()

snyk_server = MCPServerStdio(
    "snyk",
    args=["mcp", "-t", "stdio"],
    env={"SNYK_TOKEN": os.getenv("SNYK_TOKEN", "")},
    timeout=60,
)
model = BedrockConverseModel("anthropic.claude-3-haiku-20240307-v1:0")
agent = Agent(
    model=model,
    name="snyk-agent",
    mcp_servers=[snyk_server],
    system_prompt="""You are a security engineer using Snyk to find and fix open source dependency vulnerabilities.

Supported ecosystems:
- Python: pyproject.toml, requirements.txt, Pipfile
- Java / Kotlin: pom.xml, build.gradle, build.gradle.kts
- TypeScript / Node.js: package.json

Your task:
1. Use ONLY the Snyk open source (SCA) scanning tool — do NOT run code analysis, container,
   infrastructure-as-code, or any other scan type.
2. Detect which ecosystems are present in the project by checking for the manifest files above.
   Use read_file to read each manifest file before scanning.
   Scan each detected ecosystem separately.
3. For each vulnerability found across all ecosystems:
   - FIX it if severity is CRITICAL or HIGH by using write_file to update the appropriate
     manifest file (pyproject.toml, requirements.txt, pom.xml, build.gradle,
     build.gradle.kts, or package.json) with the safe version.
   - When choosing the safe version, ALWAYS prefer the minimum version that fixes the issue
     within the SAME major version (e.g., prefer >=3.26.2,<4.0.0 over ^4.x).
     Only bump to a new major version if no safe fix exists in the current major version series.
     This avoids breaking compatibility with other packages that pin to the current major version.
   - SKIP it if severity is MEDIUM or LOW — just note it was skipped.
4. After all fixes, re-scan each ecosystem to confirm critical/high issues are resolved.
5. Provide a summary grouped by ecosystem: what was fixed, what was skipped, and any remaining issues.""",
)


@agent.tool_plain
def read_file(path: str) -> str:
    """Read the contents of a file."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception as e:
        return f"Error reading file: {e}"


@agent.tool_plain
def write_file(path: str, content: str) -> str:
    """Write content to a file, overwriting it completely."""
    try:
        Path(path).write_text(content, encoding="utf-8")
        return f"Successfully wrote {path}"
    except Exception as e:
        return f"Error writing file: {e}"


@agent.tool_plain
def list_files(directory: str) -> str:
    """List files in a directory (non-recursive)."""
    try:
        entries = sorted(Path(directory).iterdir())
        return "\n".join(str(e) for e in entries)
    except Exception as e:
        return f"Error listing directory: {e}"


async def main():
    if len(sys.argv) > 1:
        project_dir = os.path.abspath(sys.argv[1])
    else:
        project_dir = input("Enter the path to the project to scan: ").strip()
        project_dir = os.path.abspath(project_dir)

    if not os.path.isdir(project_dir):
        print(f"Error: '{project_dir}' is not a valid directory.")
        sys.exit(1)

    snyk_trust_folder(project_dir)
    print(f"\nScanning project: {project_dir}")
    print("Open source scan only — fixing CRITICAL and HIGH, skipping MEDIUM and LOW...\n")

    async with agent.run_mcp_servers():
        result = await agent.run(
            f"Run an open source dependency scan (SCA only) on the project at '{project_dir}'. "
            "Detect all supported ecosystems (Python, Java/Kotlin, TypeScript/Node.js) by checking "
            "for their manifest files, then scan each one. "
            "Fix all CRITICAL and HIGH severity vulnerabilities. Skip MEDIUM and LOW. "
            "Then provide a clear summary grouped by ecosystem: what was fixed, what was skipped, "
            "and any remaining issues."
        )

    print(result.output)


if __name__ == "__main__":
    asyncio.run(main())
