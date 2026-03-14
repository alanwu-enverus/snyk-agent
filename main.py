import asyncio
import os

import logfire
from dotenv import load_dotenv

from snyk_agent import SnykAgent

logfire.configure()
logfire.instrument_pydantic_ai()
load_dotenv()


PROJECTS = [
    "/Users/alan.wu/ghoildex/alan.wu/opencontract-rest",
    "/Users/alan.wu/ghoildex/alan.wu/agent-app",
    "/Users/alan.wu/ghoildex/alan.wu/extraction-rest",
]


async def main():
    agent = SnykAgent()
    for dir in PROJECTS:
        project_dir = os.path.abspath(dir)
        if not os.path.isdir(project_dir):
            print(f"Skipping '{project_dir}': not a valid directory.")
            continue
        await agent.run(project_dir)


if __name__ == "__main__":
    asyncio.run(main())
