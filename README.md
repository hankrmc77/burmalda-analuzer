# BURMALDA ANALYZER
### AI-Powered Incident Response Agent
**SANS Find Evil! Hackathon 2026** | Direct Agent Extension

---

## What it does

BURMALDA ANALYZER is an autonomous incident response agent that monitors authentication logs, detects threats in real time, and uses Claude AI to analyze suspicious activity — all without human intervention.

When an IP address accumulates enough failed login attempts, the agent automatically:
1. Detects the threat level (LOW / MEDIUM / HIGH)
2. Looks up geolocation of the attacker
3. Sends the data to Claude for AI analysis
4. Returns a verdict (BLOCK / MONITOR / INVESTIGATE) with confidence rating
5. Logs every step with timestamps for full audit trail

---

## Architecture

```
[Log Source] → [Threat Detector] → [Claude AI Engine] → [Structured Output]
                                          ↓
                                  [Execution Logger]
                                  agent_execution.log
```

**Pattern used:** Direct Agent Extension  
**Model:** claude-opus-4-5  
**Self-correction:** Agent flags LOW confidence findings for human review via SELF-CHECK field

---

## Quick Start

### Requirements
```bash
pip3 install anthropic --break-system-packages
```

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/burmalda-analyzer
cd burmalda-analyzer
```

Open `burmalda_analyzer.py` and set your API key:
```python
ANTHROPIC_API_KEY = "sk-ant-..."
```

### Run
```bash
python3 burmalda_analyzer.py
```

---

## Features

| Feature | Description |
|--------|-------------|
| **Live Monitoring** | Streams log entries, auto-detects threats |
| **AI Auto-Analysis** | Claude analyzes MEDIUM/HIGH threats automatically |
| **File Analysis** | Parse existing log files |
| **AI Chat** | Ask questions about threats, IPs, attack patterns |
| **Execution Logs** | Full audit trail in `agent_execution.log` |
| **Geo Lookup** | IP geolocation via ip-api.com |

---

## AI Response Format

For every MEDIUM/HIGH threat, the agent returns:
```
VERDICT: BLOCK
CONFIDENCE: HIGH
REASONING: IP shows classic brute-force SSH pattern
ACTION: Add to firewall blocklist immediately
SELF-CHECK: No prior context on this IP — recommend cross-checking threat intel
```

---

## Log Format

All agent actions are logged to `agent_execution.log`:
```json
{"timestamp": "2026-05-19T10:23:01Z", "event": "threat_detected", "data": {"ip": "45.33.32.156", "level": "HIGH", "fails": 14}}
{"timestamp": "2026-05-19T10:23:02Z", "event": "ai_analysis_complete", "data": {"ip": "45.33.32.156", "tokens_used": 187}}
```

---

## Test Data

To test the file analyzer, create `test.log`:
```
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
192.168.1.100 FAIL
10.0.0.5 SUCCESS
45.33.32.156 FAIL
45.33.32.156 FAIL
45.33.32.156 FAIL
```

Then run option `[1] Analyze log file` and enter `test.log`.

---

## Accuracy & Limitations

- AI analysis depends on Claude API availability
- Geo lookup requires internet connection
- Current version uses simulated logs in live mode (real auth.log integration: `tail -f /var/log/auth.log`)
- Confidence ratings are self-reported by the AI — human verification recommended for HIGH severity findings

---

## Built With

- Python 3
- Anthropic Claude API (claude-opus-4-5)
- ip-api.com (geolocation)
- Protocol SIFT compatible

---

## License

MIT License — open source, free to use and extend.

---

*Built by Pavel | Digital College Almaty | Kazakhstan*
# burmalda-analuzer
