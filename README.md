# CAGE — Controlled Autonomous Generation Engine

**An autonomous penetration testing copilot powered by Meta Muse Spark Open.**

CAGE is an autonomous penetration testing agent built for offensive security researchers. It automates the repetitive parts of a pentest (attack-surface mapping, API endpoint discovery, and testing for common vulnerabilities) allowing human researchers to focus on complex exploitation and business logic flaws.

Meta Muse Spark Open is CAGE's reasoning engine. It analyzes security information, plans and guides testing tasks, and flags potential vulnerabilities. Everything it proposes passes through deterministic safety and validation layers, so CAGE stays safe, predictable, and reliable while remaining highly capable.

Built by [Tufail Athar](https://github.com/tufailathar)

## The Problem

Penetration testers spend valuable time on repetitive reconnaissance, attack-surface mapping, and baseline vulnerability testing.

Existing scanners can produce false positives and unverified findings, increasing manual investigation and triage effort.

This leaves less time to focus on complex exploitation, business logic flaws, and deeper security analysis.

## Features

- **Autonomous Recon:** Automatically discovers, maps, and tests the target's attack surface.
- **Persistent Whiteboard:** Uses a JSON state file (`state.json`) to track testing progress and remember previously tested items.
- **Browser-Based Fetching:** Uses headless Chromium (`browser_fetch`) as a fallback when standard `curl` requests fail, including on JavaScript-rendered pages.
- **Bouncer Validation:** Filters potential false positives, including SPA shells, informational noise, and invalid or `"N/A"` payloads.
- **Live Dashboard:** Displays agent activity and testing progress at `http://127.0.0.1:7777`.
- **Safe Execution:** Validates shell commands against a deny-list and enforces strict timeouts to reduce the risk of destructive actions or runaway processes.

## Why Meta Muse Spark Open

- **Open weights, self-hostable:** Run the reasoning engine on your own infrastructure so sensitive target data and findings do not have to leave your environment.
- **Long context:** Reason over large scan outputs, API specifications, and HTTP traces, subject to the model-serving configuration.
- **Customizable:** Open weights allow further training and fine-tuning on security data, subject to the model license.

## Installing

CAGE is designed to run on **Kali Linux** (or a similar environment with standard security tools installed). Python 3.10+ is required.

```bash
git clone https://github.com/tufailathar/cage.git
cd cage
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

For API configuration, CAGE requires a Baseten API key to access Meta Muse Spark.

Create the `secrets/` directory if it doesn't exist, then create a `.env` file inside it and add your key:

```bash
mkdir -p secrets
nano secrets/.env
```

Add the following:

```env
BASETEN_API_KEY=your_api_key_here
```

## Using CAGE

Getting started is as easy as running `cage run`.

```bash
cage run
```

## Safety & Scope

CAGE is designed for authorized security testing in controlled environments, including CTF labs and explicitly authorized targets. Use responsibly.

Running CAGE against any system you do not own or do not have explicit written permission to test is illegal and strictly prohibited.

## License

Distributed under the MIT License. See the `LICENSE` file for more information.
