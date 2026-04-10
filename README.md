---
title: NetPwn OpenEnv
emoji: 🛡️
colorFrom: green
colorTo: blue
sdk: docker
pinned: true
license: mit
short_description: Penetration Testing RL Environment for OpenEnv
---

# 🛡️ NetPwn — Penetration Testing RL Environment

**Meta × PyTorch OpenEnv Hackathon Submission**

An AI agent performs ethical penetration testing against a simulated corporate network.
Train LLMs to think like security professionals.

## Endpoints (OpenEnv Standard)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/reset` | POST | Start new episode |
| `/step`  | POST | Execute action |
| `/state` | GET  | Current state |
| `/schema`| GET  | Action/observation schema |
| `/ws`    | WS   | WebSocket for persistent sessions |

## Tasks

- `network_recon` — Easy: Discover all hosts/services (15 steps)
- `vulnerability_exploit` — Medium: Exploit CVEs for access (30 steps)  
- `ctf_capture` — Hard: Full attack chain + flag capture (50 steps)

[GitHub](https://github.com/Shivaram304/cybersec-rl-openenv)
