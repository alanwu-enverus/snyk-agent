import asyncio
import os
import time

import logfire
from dotenv import load_dotenv

from java_agent import JavaAgent
from typescript_agent import TypeScriptAgent
from python_agent import PythonAgent

logfire.configure()
logfire.instrument_pydantic_ai()
load_dotenv()


BASE_PATH = "/Users/alan.wu/github/enverus-ba"

PROJECTS = [
    # (f"{BASE_PATH}/opencontract-rest", JavaAgent()),
    # (f"{BASE_PATH}/agent-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/ai-file-ingestor", TypeScriptAgent()),
    # (f"{BASE_PATH}/config-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-document-exchange-rest", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-ep-theme", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-ep-ui-components", TypeScriptAgent()),
    # (f"{BASE_PATH}/ba-oi-eslint-plugin", TypeScriptAgent()),
    # (f"{BASE_PATH}/invoice-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/report-app", TypeScriptAgent()),
    (f"{BASE_PATH}/extraction-rest", PythonAgent()),
    # (f"{BASE_PATH}/report-rest", PythonAgent()),
    # (f"{BASE_PATH}/sentry-rest", PythonAgent()),
]

SCAN_OPTIONS = dict(all_projects=True, detection_depth=10, dev=True)


async def main():
    total_start = time.time()
    for project_path, agent in PROJECTS:
        project_dir = os.path.abspath(project_path)
        if not os.path.isdir(project_dir):
            print(f"Skipping '{project_dir}': not a valid directory.")
            continue
        start = time.time()
        
        await agent.run(project_dir, **SCAN_OPTIONS)
        
        elapsed = time.time() - start
        print(f"[{os.path.basename(project_dir)}] completed in {elapsed:.1f}s")
        os.system(f'open -a "IntelliJ IDEA" "{project_dir}"')
    total_elapsed = time.time() - total_start
    print(f"\nTotal time: {total_elapsed:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
