# Snyk Agent

An AI-powered security agent that scans open source dependencies for CRITICAL and HIGH vulnerabilities and auto-fixes them using [Snyk](https://snyk.io) MCP and Claude via AWS Bedrock.

**Supported ecosystems:** Python (`pyproject.toml`, `requirements.txt`), Java/Kotlin (`pom.xml`, `build.gradle`), TypeScript/Node.js (`package.json`)

---

## Prerequisites

- [uv](https://docs.astral.sh/uv/) — Python package manager
- [Node.js](https://nodejs.org/) — required for Snyk CLI
- AWS CLI with SSO access to Bedrock
- Snyk account

---

## Configuration

### 1. Snyk Token

1. Log in to [app.snyk.io](https://app.snyk.io)
2. Go to **Account Settings** → **General** → **Auth Token**
3. Copy your token
4. Run:
   ```bash
   snyk auth <YOUR_TOKEN>
   ```
   Or set it as an environment variable (see `.env` setup below).

### 2. AWS SSO Login (Bedrock)

The agent uses Claude via AWS Bedrock. Authenticate with your AWS SSO profile:

```bash
aws sso login --profile <your-profile>
```

To set your profile for the session:

```bash
export AWS_PROFILE=<your-profile>
```

Verify it works:

```bash
aws sts get-caller-identity
```

> Tokens expire after a few hours. Re-run `aws sso login` when you see `ExpiredTokenException`.

### 3. Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env   # if available, otherwise create manually
```

`.env` contents:

```env
SNYK_TOKEN=your_snyk_token_here
```

---

## Project Setup

### Install Snyk CLI

```bash
npm install -g snyk
```

Verify:

```bash
snyk --version
```

### Fix `python` not found (macOS)

Snyk requires `python` on PATH. On macOS, only `python3` is installed by default:

```bash
mkdir -p ~/bin
ln -sf $(which python3) ~/bin/python
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Install Python Dependencies

```bash
uv sync
```

This creates a `.venv` and installs all dependencies from `pyproject.toml`.

---

## Running

```bash
uv run main.py /path/to/your/project
```

**Example:**

```bash
uv run main.py /Users/alan.wu/github/myorg/my-service
```

The agent will:

1. Auto-trust the project folder in Snyk
2. Detect ecosystems by checking for manifest files
3. Run open source (SCA) scans per ecosystem
4. Fix CRITICAL and HIGH vulnerabilities (minimum safe version within the same major version)
5. Skip MEDIUM and LOW
6. Re-scan to confirm fixes
7. Print a summary grouped by ecosystem

---

## Notes

- Only open source (SCA) scans are performed — no SAST, container, or IaC scans
- After the agent updates `pyproject.toml`, run `poetry lock` or `uv lock` to regenerate the lockfile
- Major version bumps are avoided unless no safe fix exists in the current major series

---

## TODO: Sub-agent Architecture

Refactor into specialized sub-agents for better separation of concerns:

### a. Scan & Fix Sub-agent (Snyk MCP)
- Invoke Snyk MCP to scan the project for open source vulnerabilities
- Auto-update manifest files (`pyproject.toml`, `pom.xml`, `package.json`, etc.) with safe versions
- Stay within the same major version unless no fix exists

### b. Verification Sub-agent (Terminal / Snyk CLI) — _TBD: is this needed?_
- After the fix sub-agent updates manifests, run `snyk test` directly via terminal to confirm no CRITICAL/HIGH issues remain
- Useful as a double-check since MCP and CLI may behave differently
- Consider skipping if MCP re-scan in step (a) is sufficient

### c. PR Sub-agent (GitHub MCP)
- Create a new branch (e.g., `fix/snyk-vulnerabilities-<date>`)
- Commit and push the updated manifest and lockfiles
- Open a Pull Request with a summary of what was fixed



1. snyk cli must be install
2. snyk must be version high than ? 
3. snyk auth and get token to set at .env
4. to view pydantic ai firelog, need to register account. it is free
5. aws access token and aws sso login 
6. the scanning project must run install dependencies before run this app
7. uv run main.py
