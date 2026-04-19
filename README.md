# Project Swarm

Autonomous multi-agent AI that hunts, proves, and patches zero-day vulnerabilities at machine speed — no human in the loop.

![CI](https://github.com/spacewarriorgitxdevOP/project-swarm/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

## What it does

Project Swarm ingests any Git repository, builds a deep AST-based code graph, and uses Claude to generate ranked vulnerability hypotheses — then proves each one in an isolated gVisor sandbox before generating and auditing a fix. The entire loop from repo URL to verified patch runs without human intervention, at the speed of compute rather than the speed of triage.

## Architecture
## Agents

| Agent | Role | Key Technology |
|-------|------|---------------|
| Mapper | Clones repo, parses source into an AST-based code graph | Tree-sitter, Neo4j |
| Hunter | Generates ranked vulnerability hypotheses from the code graph | Claude API (Anthropic) |
| Sandboxer | Proves or disproves each hypothesis via live exploit execution | Docker, gVisor |
| Patcher | Generates a remediation diff and opens a pull request | Claude API, GitPython |
| Auditor | Reviews the patch for correctness, regressions, and new risk | Claude API, pytest |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| AST Parsing | Tree-sitter |
| LLM | Claude API (Anthropic) |
| Graph Database | Neo4j AuraDB |
| Sandboxing | Docker + gVisor (runsc) |
| Data Validation | Pydantic v2 |
| CI/CD | GitHub Actions |

## Quick Start

```bash
git clone https://github.com/spacewarriorgitxdevOP/project-swarm.git
cd project-swarm

pip install -r requirements.txt

cp .env.example .env
# Fill in ANTHROPIC_API_KEY, NEO4J_*, and GITHUB_TOKEN

python scripts/run_scan.py --repo https://github.com/org/target-repo --branch main
```

## Roadmap

- [x] Core models and pipeline state machine
- [x] Exception hierarchy and structured logging
- [ ] Mapper agent — Tree-sitter AST parser
- [ ] Hunter agent — LLM hypothesis engine
- [ ] Sandboxer agent — Docker + gVisor exploit prover
- [ ] Patcher agent — fix generator and PR submitter
- [ ] Auditor agent — patch reviewer
- [ ] Knowledge graph persistence — Neo4j
- [ ] Bug bounty automation pipeline

## License

MIT

## Built by

[spacewarriorgitxdevOP](https://github.com/spacewarriorgitxdevOP)
