import asyncio
import os
import subprocess
import time

import logfire
from dotenv import load_dotenv

from java_agent import JavaAgent
from typescript_agent import TypeScriptAgent
from python_agent import PythonAgent

logfire.configure()
logfire.instrument_pydantic_ai()
load_dotenv()


BASE_PATH = "/Users/alan.wu/Downloads/temp-src"

PROJECTS = [
    # (f"{BASE_PATH}/opencontract-rest", JavaAgent()),
    # (f"{BASE_PATH}/agent-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/ai-file-ingestor", TypeScriptAgent()),
    # (f"{BASE_PATH}/config-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-document-exchange-rest", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-ep-theme", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-ep-ui-components", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-eslint-plugin", TypeScriptAgent()),
    (f"{BASE_PATH}/ba-oi-config-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/report-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/extraction-rest", PythonAgent()), 
    # (f"{BASE_PATH}/report-rest", PythonAgent()),
    # (f"{BASE_PATH}/sentry-rest", PythonAgent()),
]

SCAN_OPTIONS = dict(all_projects=True, detection_depth=10, dev=True)

BRANCH_NAME = "P2P-106724-update-dependencies"
COMMIT_MESSAGE = """\
P2P-106724 security vulnerability

Description: update dependencies

Co-Authored-By: @Lumen"""


def git_create_branch(project_dir: str, branch_name: str) -> bool:
    """Checkout main, pull latest, then create and switch to a new branch."""
    try:
        subprocess.run(["git", "checkout", "main"], cwd=project_dir, check=True, capture_output=True)
        subprocess.run(["git", "pull"], cwd=project_dir, check=True, capture_output=True)
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=project_dir, check=True, capture_output=True)
        print(f"Created branch '{branch_name}' in {project_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error creating branch in {project_dir}: {e.stderr.decode().strip()}")
        return False


def git_commit_if_changed(project_dir: str, commit_message: str) -> bool:
    """Stage all changes and commit if anything changed. Returns True if committed."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=project_dir,
        capture_output=True,
        text=True,
    )
    if not result.stdout.strip():
        print(f"No changes to commit in {project_dir}")
        return False
    try:
        subprocess.run(["git", "add", "-A"], cwd=project_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", commit_message], cwd=project_dir, check=True, capture_output=True)
        print(f"Committed changes in {project_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error committing in {project_dir}: {e.stderr.decode().strip()}")
        return False


async def main():
    total_start = time.time()
    for project_path, agent in PROJECTS:
        project_dir = os.path.abspath(project_path)
        if not os.path.isdir(project_dir):
            print(f"Skipping '{project_dir}': not a valid directory.")
            continue
        start = time.time()

        git_create_branch(project_dir, BRANCH_NAME)

        await agent.run(project_dir, **SCAN_OPTIONS)
        
        git_commit_if_changed(project_dir, COMMIT_MESSAGE)

        elapsed = time.time() - start
        print(f"[{os.path.basename(project_dir)}] completed in {elapsed:.1f}s")
    total_elapsed = time.time() - total_start
    print(f"\nTotal time: {total_elapsed:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
