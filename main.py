import asyncio
import os

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
    (f"{BASE_PATH}/agent-app", TypeScriptAgent()),
    # (f"{BASE_PATH}/extraction-rest", PythonAgent()),
]

async def main():
    for project_path, agent in PROJECTS:
        project_dir = os.path.abspath(project_path)
        if not os.path.isdir(project_dir):
            print(f"Skipping '{project_dir}': not a valid directory.")
            continue
        await agent.run(project_dir)
        os.system(f'open -a "IntelliJ IDEA" "{project_dir}"')


if __name__ == "__main__":
    asyncio.run(main())
