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

NetPwn is a real-world cybersecurity Reinforcement Learning environment built strictly according to the OpenEnv framework. It trains AI agents to act as ethical penetration testers against a simulated corporate network (`192.168.1.0/24`). 

Unlike simple games or toy environments, NetPwn requires the agent to understand network topologies, identify unpatched real-world CVEs, escalate privileges, maintain stealth against Intrusion Detection Systems (IDS), and exfiltrate flags.

🔗 **[GitHub Repository](https://github.com/Shivaram304/cybersec-rl-openenv)** | 🔗 **[Hugging Face Space](https://huggingface.co/spaces/shivarammore89/netpwn)**

---

## 🏗️ OpenEnv Implementation

This environment fully implements the OpenEnv specification:
- Uses strongly-typed `Pydantic` JSON schemas.
- Interfaces via `openenv.core.env_server.interfaces.Environment`.
- Exposes compliant `/reset`, `/step`, `/state`, and WebHook endpoints.
- Hosted natively as a Docker Space on Hugging Face.

---

## 🎮 Action & Observation Spaces

### Action Space
The agent responds with a JSON object defining its attack vector:
```json
{
  "action_type": "scan", // Options: scan, exploit, brute_force, escalate, exfiltrate
  "target_ip": "192.168.1.1", 
  "technique": "cve_2021_41773" // Optional technique selection
}
```

### Observation Space
The environment returns the current network state, IDS heat, and step results:
```json
{
  "known_hosts": [{"ip": "192.168.1.2", "status": "online", "open_ports": [80], "access": "none"}],
  "ids_alert": 0.45, 
  "current_pos": "192.168.1.1",
  "flags_captured": 1,
  "action_result": "Successfully exploited cve_2021_41773. System access: user.",
  "reward": 0.5,
  "done": false
}
```

---

## 📋 The 3 Curriculum Tasks & Reward Logic

The environment ships with `openenv.yaml` defining a progressive curriculum.
**Grading & Reward Function:** Rewards are `[0.0 - 1.0]` normalized. Partial progress (discovering network hosts) grants micro-rewards. Tripping the IDS (rating > 80%) instantly results in steep negative penalties `(-0.5)` and terminates the episode.

1. **`network_recon` (Easy)**
   - **Goal:** Discover all live machines and open ports on the simulated subnet.
   - **Grader:** Score based on the percentage of total services mapped vs. IDS noise generated.

2. **`vulnerability_exploit` (Medium)**
   - **Goal:** Analyze the recon data, select a vulnerable host, and successfully execute a CVE exploit to gain initial `user` access.
   - **Grader:** Graded on successful exploitation, correct technique pairing, and stealth.

3. **`ctf_capture` (Hard)**
   - **Goal:** Full cyber kill-chain. The agent must recon, exploit a machine, execute horizontal privilege escalation (`root`), and finally exfiltrate the hidden flags.
   - **Grader:** Strict `[0, 1]` based entirely on final CTF flags captured divided by total flags.

---

## 🚀 Setup & Inference Instructions

### Prerequisites
- Python 3.10+
- `openenv-core`

### 1. Local Testing
```bash
# Clone the repository
git clone https://github.com/Shivaram304/cybersec-rl-openenv.git
cd cybersec-rl-openenv

# Start the environment server locally
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

### 2. Running the Inference Script (Baseline)
A compliant `inference.py` script is provided at the repository root. It hits the remote Hugging Face APIs directly, executing actions via LLMs, and formatting `[START]`, `[STEP]`, and `[END]` JSON log streams.

1. Get a free OpenRouter/HF Inference token.
2. Set your environment variables:
```bash
export HF_TOKEN="your_token_here"
export MODEL_NAME="meta-llama/llama-3.3-8b-instruct:free"

# Run the OpenEnv agent
python inference.py
```
