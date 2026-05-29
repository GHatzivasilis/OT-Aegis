# OT-Aegis
**Safe Supervision Architecture for AI-Controlled Industrial Systems**

OT-Aegis is a research prototype demonstrating a layered safety and cybersecurity supervision architecture for AI-assisted Industrial Control Systems (ICS) / Operational Technology (OT).

The prototype implements a **defense-in-depth runtime assurance architecture** in which AI-generated control commands are never trusted directly. Instead, they are filtered through a software supervisory shield and then independently validated by deterministic PLC logic before affecting the physical process.

# Citation

If you use this prototype in academic work, please cite the associated publication: "OT-Aegis: AI-Driven Security for Operational Technology and Industrial Systems", G. Hatzivasilis and D. Pezaros.
---

## Architecture

```text
+-----------------------+
|   AI Agent Emulator   |
|  (adaptive / unsafe)  |
+-----------+-----------+
            |
            | MQTT
            v
+-----------------------+
|   Software Shield     |
| Contextual validation |
| + cyber-aware checks  |
+-----------+-----------+
            |
            | PLC-facing command image
            v
+-----------------------+
|   PLC Supervisor      |
| Deterministic logic   |
| Final enforcement     |
+-----------+-----------+
            |
            v
+-----------------------+
|   Physical Process    |
+-----------------------+
```

---

## Core Design Principle

OT-Aegis explicitly separates intelligence, supervision, and deterministic enforcement.

### AI Agent
The AI agent represents an adaptive decision-making component capable of generating control recommendations.

Characteristics:

- adaptive
- non-deterministic
- potentially unsafe
- potentially compromised
- operationally untrusted

The AI agent is intentionally **not trusted** to directly control the industrial process.

---

### Software Shield
The Software Shield acts as the contextual runtime assurance layer.

Responsibilities include:

- message schema validation
- confidence evaluation
- freshness checking
- replay detection
- soft bounds enforcement
- rate-of-change supervision
- process plausibility checks
- denial-of-service detection
- maintenance lockout
- cyber alert escalation

The shield may:

- allow commands
- downgrade commands
- request deterministic fallback
- block commands

---

### PLC Supervisor
The PLC acts as the deterministic final decision-maker.

Responsibilities include:

- heartbeat supervision
- timing validation
- hard engineering bounds checking
- interlock enforcement
- process safety logic
- mode validation
- deterministic fallback
- fail-safe shutdown

The PLC does **not trust** either:

- the AI agent
- the Software Shield

It independently validates all incoming commands.

---

## Research Motivation

Direct deployment of AI inside industrial control logic introduces serious engineering and certification challenges:

- AI behavior is adaptive and non-deterministic
- functional safety certification requires deterministic validated logic
- model updates invalidate certification assumptions
- AI expands the cybersecurity attack surface

OT-Aegis demonstrates an alternative architecture:

> **AI remains outside the trusted control core and is constrained by supervisory deterministic safety enforcement.**

This design is inspired by:

- Runtime Assurance
- Simplex Architecture
- Black-Box Simplex
- industrial safety envelope supervision

---

# Components

---

## 1. AI Agent Emulator

File:

```text
mqtt_agent_publisher.py
```

This component emulates an AI control agent.

Published MQTT topics:

```text
ics/ai_agent/commands
ics/ai_agent/status
```

Supported behaviors:

### normal
Valid, stable, high-confidence recommendations.

Example:

```json
{
  "sequence_id": 42,
  "pump_speed": 48.5,
  "valve_open": true,
  "confidence": 0.93
}
```

---

### faulty
Simulates unstable or low-confidence AI outputs.

Examples:

- noisy recommendations
- oscillatory control
- low confidence
- invalid commands

---

### compromised
Simulates clearly malicious unsafe AI behavior.

Example:

```json
{
  "pump_speed": 120.0,
  "valve_open": false
}
```

---

### stealthy
Simulates gradual malicious escalation while remaining within nominal operating bounds.

Used to emulate:

- slow drift attacks
- stealth manipulation
- bounded malicious behavior

---

### stale
Simulates replay-like stale command injection.

Characteristics:

- old timestamps
- repeated sequence IDs
- replay behavior

---

### dos_flood
Simulates denial-of-service flooding.

Example:

```bash
python mqtt_agent_publisher.py --behavior dos_flood --period 0.01
```

This produces approximately:

```text
100 commands / second
```

---

## 2. Software Shield

File:

```text
mqtt_software_shield_safety_profile.py
```

This component implements the contextual runtime assurance layer.

Subscribed topic:

```text
ics/ai_agent/commands
```

Published topics:

```text
ics/shield/validated_commands
ics/shield/plc_image
ics/shield/alerts
ics/shield/metrics
```

---

### Decision Codes

| Code | Meaning |
|------|---------|
| 1 | ALLOW |
| 2 | DOWNGRADE |
| 3 | FALLBACK_REQUEST |
| 4 | BLOCK |

---

### Diagnostic Reason Codes

| Code | Meaning |
|------|---------|
| 0 | NONE |
| 10 | MALFORMED |
| 11 | LOW_CONFIDENCE |
| 12 | STALE |
| 13 | REPLAY |
| 14 | SOFT_BOUND_VIOLATION |
| 15 | RATE_OF_CHANGE |
| 16 | PROCESS_IMPLAUSIBLE |
| 17 | DOS_DETECTED |
| 18 | MAINTENANCE_LOCKOUT |
| 19 | CYBER_ALERT |
| 99 | INTERNAL_ERROR |

---

### Shield Checks

Implemented supervision logic includes:

- message parsing validation
- confidence threshold enforcement
- stale command rejection
- replay detection
- soft engineering bounds
- rate-of-change anomaly detection
- process plausibility validation
- DoS rate monitoring
- maintenance mode lockout
- cyber alert escalation

---

## PLC Command Image

Published to:

```text
ics/shield/plc_image
```

Example:

```json
{
  "shield_enable": true,
  "seq_id": 42,
  "heartbeat": 103,
  "valid": true,
  "decision_code": 1,
  "risk_score": 10,
  "pump_speed_cmd_x10": 455,
  "valve_open_cmd": true,
  "fallback_required": false,
  "safe_stop_required": false,
  "reason_code": 0
}
```

Engineering scaling:

| Field | Meaning |
|------|---------|
| pump_speed_cmd_x10 | 45.5% → 455 |

This interface is intentionally flat and deterministic for PLC / Safety PLC compatibility.

---

## 3. PLC Supervisor

File:

```text
AI_SafetySupervisor.scl
```

This component implements deterministic supervisory logic in Siemens SCL.

Responsibilities:

- heartbeat monitoring
- command timing supervision
- hard bounds enforcement
- process safety validation
- interlock enforcement
- mode validation
- deterministic fallback
- fail-safe shutdown

Decision priority:

```text
Emergency / unsafe condition
    -> FAIL SAFE

Valid shield output + PLC checks pass
    -> APPLY SHIELD COMMAND

Recoverable issue
    -> DETERMINISTIC FALLBACK

Unknown unsafe condition
    -> FAIL SAFE
```

---

## Safety PLC Compatibility

The current demo executes on a standard PLC.

However, the implementation intentionally follows conventions compatible with migration toward fail-safe PLC environments:

- deterministic logic
- flat interfaces
- integer engineering values
- explicit decision codes
- explicit diagnostic codes
- no dynamic runtime behavior

For production deployment, migration to certified safety hardware would require:

- fail-safe PLC hardware
- TÜV-certified safety logic blocks
- safety memory partitioning
- fail-safe task scheduling
- certified engineering workflows

---

## 4. MQTT Monitor

File:

```text
mqtt_monitor.py
```

This utility provides runtime visibility for the demo.

Subscribed topics:

```text
ics/ai_agent/commands
ics/ai_agent/status
ics/shield/validated_commands
ics/shield/plc_image
ics/shield/alerts
ics/shield/metrics
```

Features:

- human-readable MQTT monitoring
- PLC image visualization
- debugging support
- demo observation
- graceful shutdown via CTRL+C

---

# Requirements

Python:

```text
Python 3.10+
```

Install dependencies:

```bash
pip install paho-mqtt psutil
```

MQTT broker required.

Recommended broker:

Eclipse Mosquitto

---

# Running the Demo

---

## 1. Start MQTT Broker

Example:

```bash
mosquitto
```

---

## 2. Start the Software Shield

```bash
python mqtt_software_shield_safety_profile.py
```

Optional maintenance mode:

```bash
python mqtt_software_shield_safety_profile.py --maintenance
```

Optional cyber alert mode:

```bash
python mqtt_software_shield_safety_profile.py --cyber-alert
```

---

## 3. Start the Monitor

```bash
python mqtt_monitor.py
```

---

## 4. Start the AI Agent

Normal:

```bash
python mqtt_agent_publisher.py --behavior normal
```

Faulty:

```bash
python mqtt_agent_publisher.py --behavior faulty
```

Compromised:

```bash
python mqtt_agent_publisher.py --behavior compromised
```

Stealthy:

```bash
python mqtt_agent_publisher.py --behavior stealthy
```

Replay:

```bash
python mqtt_agent_publisher.py --behavior stale
```

DoS flood:

```bash
python mqtt_agent_publisher.py --behavior dos_flood --period 0.01
```

---

# Experimental Scenarios

Suggested evaluation scenarios:

- benign AI operation
- unstable AI outputs
- malicious compromise
- stealth drift manipulation
- stale command injection
- replay attacks
- denial-of-service flooding
- maintenance lockout
- cyber alert escalation
- software shield shutdown
- PLC fallback activation
- PLC fail-safe transition

---

# Research Contribution

OT-Aegis demonstrates a cybersecurity-aware dual-layer assurance architecture for industrial AI supervision.

Core contribution:

```text
AI Agent
    ->
Software Runtime Shield
    ->
Deterministic PLC Enforcement
    ->
Physical Process
```

This enables:

- safe AI experimentation
- industrial runtime assurance
- deterministic supervisory enforcement
- OT cybersecurity-aware control supervision

---

# License

This project is licensed under the Apache License 2.0.

---

# Disclaimer

This repository is a research prototype intended for demonstration and experimentation.

It is **not certified safety software** and must not be used directly in production industrial safety environments without appropriate engineering validation, certification, and safety assessment.
