#!/usr/bin/env python3
"""
OT-Aegis Safety-Profile MQTT Software Shield.

This module implements the software supervisory shield of the OT-Aegis
prototype. The shield receives AI-generated operational recommendations over
MQTT, validates them using communication-aware and process-aware checks, and
publishes both human-readable supervision results and a deterministic
PLC-facing command image.

Subscribed MQTT topic:
    ics/ai_agent/commands

Published MQTT topics:
    ics/shield/validated_commands
    ics/shield/plc_image
    ics/shield/alerts
    ics/shield/metrics

PLC image conventions:
    pump_speed_cmd_x10:
        Pump speed percentage scaled by 10. Example: 45.5 percent -> 455.

    decision_code:
        1 = ALLOW
        2 = DOWNGRADE
        3 = FALLBACK_REQUEST
        4 = BLOCK

    risk_score:
        Integer value in the range 0..100.

Graceful shutdown:
    When CTRL+C is received, the shield publishes a final fail-safe PLC image.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple

import paho.mqtt.client as mqtt
import psutil


TOPIC_AI_COMMANDS = "ics/ai_agent/commands"
TOPIC_VALIDATED = "ics/shield/validated_commands"
TOPIC_PLC_IMAGE = "ics/shield/plc_image"
TOPIC_ALERTS = "ics/shield/alerts"
TOPIC_METRICS = "ics/shield/metrics"


# Decision codes. These are numeric because the PLC should not depend on strings.
DECISION_ALLOW = 1
DECISION_DOWNGRADE = 2
DECISION_FALLBACK = 3
DECISION_BLOCK = 4


# Diagnostic reason codes.
REASON_NONE = 0
REASON_MALFORMED = 10
REASON_LOW_CONFIDENCE = 11
REASON_STALE = 12
REASON_REPLAY = 13
REASON_SOFT_BOUND = 14
REASON_RATE_OF_CHANGE = 15
REASON_PROCESS_IMPLAUSIBLE = 16
REASON_DOS = 17
REASON_MAINTENANCE = 18
REASON_CYBER_ALERT = 19
REASON_INTERNAL_ERROR = 99


DECISION_NAMES = {
    DECISION_ALLOW: "allow",
    DECISION_DOWNGRADE: "downgrade",
    DECISION_FALLBACK: "fallback_request",
    DECISION_BLOCK: "block",
}

REASON_NAMES = {
    REASON_NONE: "none",
    REASON_MALFORMED: "malformed",
    REASON_LOW_CONFIDENCE: "low_confidence",
    REASON_STALE: "stale",
    REASON_REPLAY: "replay",
    REASON_SOFT_BOUND: "soft_bound_violation",
    REASON_RATE_OF_CHANGE: "rate_of_change",
    REASON_PROCESS_IMPLAUSIBLE: "process_implausible",
    REASON_DOS: "dos_detected",
    REASON_MAINTENANCE: "maintenance_lockout",
    REASON_CYBER_ALERT: "cyber_alert",
    REASON_INTERNAL_ERROR: "internal_error",
}


def clamp_int(value: int, lower: int, upper: int) -> int:
    """Clamp an integer value to a closed interval."""
    return max(lower, min(upper, value))


def pump_percent_to_x10(value: float) -> int:
    """Convert pump percentage to PLC integer scaling.

    Example:
        45.5 percent -> 455
    """
    return int(round(value * 10.0))


@dataclass
class ShieldConfig:
    """Runtime configuration for the Software Shield."""

    confidence_min: float = 0.75
    command_max_age_s: float = 0.5
    min_interarrival_s: float = 0.05

    soft_pump_min: float = 0.0
    soft_pump_max: float = 75.0
    max_pump_delta: float = 15.0

    fallback_pump_speed: float = 30.0
    fallback_valve_open: bool = True

    maintenance_mode: bool = False
    cyber_alert_active: bool = False


@dataclass
class PLCImage:
    """Flat deterministic image intended for PLC or Safety-PLC logic."""

    shield_enable: bool
    seq_id: int
    heartbeat: int
    valid: bool
    decision_code: int
    risk_score: int
    pump_speed_cmd_x10: int
    valve_open_cmd: bool
    fallback_required: bool
    safe_stop_required: bool
    reason_code: int


class SoftwareShield:
    """MQTT-based OT-Aegis software supervisory shield."""

    def __init__(self, client: mqtt.Client, config: ShieldConfig):
        self.client = client
        self.config = config

        self.last_sequence_id: Optional[int] = None
        self.last_pump_speed: float = 0.0
        self.last_arrival_time: Optional[float] = None
        self.heartbeat_counter: int = 0

        self.total_seen = 0
        self.total_allowed = 0
        self.total_downgraded = 0
        self.total_fallback = 0
        self.total_blocked = 0

    def on_message(self, _client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
        """MQTT callback executed when an AI command is received."""
        now = time.time()
        self.total_seen += 1

        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            self._emit({}, DECISION_BLOCK, REASON_MALFORMED, 100, None, now)
            return

        decision, reason, risk, safe_command = self.evaluate(payload, now)
        self._emit(payload, decision, reason, risk, safe_command, now)

    def evaluate(self, command: Dict[str, Any], now: float) -> Tuple[int, int, int, Optional[Dict[str, Any]]]:
        """Evaluate one AI-generated command.

        Returns:
            Tuple of (decision_code, reason_code, risk_score, safe_command).
        """

        required = ["sequence_id", "timestamp", "confidence", "pump_speed", "valve_open"]
        if not all(k in command for k in required):
            return DECISION_BLOCK, REASON_MALFORMED, 100, None

        try:
            seq_id = int(command["sequence_id"])
            timestamp = float(command["timestamp"])
            confidence = float(command["confidence"])
            pump_speed = float(command["pump_speed"])
            valve_open = bool(command["valve_open"])
        except Exception:
            return DECISION_BLOCK, REASON_MALFORMED, 100, None

        # Maintenance mode intentionally prevents direct use of AI commands.
        if self.config.maintenance_mode:
            return DECISION_FALLBACK, REASON_MAINTENANCE, 80, self._fallback_command(seq_id)

        # Rate limiting / DoS detection.
        if self.last_arrival_time is not None:
            interarrival = now - self.last_arrival_time
            if interarrival < self.config.min_interarrival_s:
                self.last_arrival_time = now
                return DECISION_FALLBACK, REASON_DOS, 85, self._fallback_command(seq_id)

        self.last_arrival_time = now

        # Freshness validation.
        age = now - timestamp
        if age > self.config.command_max_age_s or age < -1.0:
            return DECISION_FALLBACK, REASON_STALE, 75, self._fallback_command(seq_id)

        # Replay detection.
        if self.last_sequence_id is not None and seq_id <= self.last_sequence_id:
            return DECISION_FALLBACK, REASON_REPLAY, 85, self._fallback_command(seq_id)

        self.last_sequence_id = seq_id

        # Confidence validation.
        if confidence < self.config.confidence_min:
            return (
                DECISION_DOWNGRADE,
                REASON_LOW_CONFIDENCE,
                55,
                self._clamped_command(seq_id, pump_speed, valve_open),
            )

        # Cyber alert context.
        if self.config.cyber_alert_active:
            return DECISION_FALLBACK, REASON_CYBER_ALERT, 90, self._fallback_command(seq_id)

        # Software soft bounds.
        if pump_speed < self.config.soft_pump_min or pump_speed > self.config.soft_pump_max:
            return (
                DECISION_DOWNGRADE,
                REASON_SOFT_BOUND,
                65,
                self._clamped_command(seq_id, pump_speed, valve_open),
            )

        # Rate-of-change anomaly.
        if abs(pump_speed - self.last_pump_speed) > self.config.max_pump_delta:
            return (
                DECISION_DOWNGRADE,
                REASON_RATE_OF_CHANGE,
                60,
                self._clamped_command(seq_id, pump_speed, valve_open),
            )

        # Cyber-physical plausibility.
        if pump_speed > 0.0 and not valve_open:
            return DECISION_FALLBACK, REASON_PROCESS_IMPLAUSIBLE, 90, self._fallback_command(seq_id)

        self.last_pump_speed = pump_speed
        return DECISION_ALLOW, REASON_NONE, 10, {
            "sequence_id": seq_id,
            "pump_speed": pump_speed,
            "valve_open": valve_open,
        }

    def _clamped_command(self, seq_id: int, pump_speed: float, valve_open: bool) -> Dict[str, Any]:
        """Return a command constrained to the software safety envelope."""
        clamped = min(max(pump_speed, self.config.soft_pump_min), self.config.soft_pump_max)

        if not valve_open and clamped > 0.0:
            clamped = 0.0

        self.last_pump_speed = clamped

        return {
            "sequence_id": seq_id,
            "pump_speed": clamped,
            "valve_open": valve_open,
        }

    def _fallback_command(self, seq_id: int) -> Dict[str, Any]:
        """Return the deterministic fallback command generated by the shield."""
        self.last_pump_speed = self.config.fallback_pump_speed

        return {
            "sequence_id": seq_id,
            "pump_speed": self.config.fallback_pump_speed,
            "valve_open": self.config.fallback_valve_open,
        }

    def _build_plc_image(
        self,
        command: Dict[str, Any],
        decision: int,
        reason: int,
        risk_score: int,
        safe_command: Optional[Dict[str, Any]],
    ) -> PLCImage:
        """Build the flat PLC-facing image for downstream deterministic logic."""
        self.heartbeat_counter = (self.heartbeat_counter + 1) % 2147483647

        seq_id = int(command.get("sequence_id", 0)) if isinstance(command, dict) else 0
        safe_command = safe_command or {}

        if decision == DECISION_BLOCK:
            pump_speed_x10 = 0
            valve_open = False
        else:
            pump_speed = float(safe_command.get("pump_speed", 0.0))
            pump_speed_x10 = pump_percent_to_x10(pump_speed)
            valve_open = bool(safe_command.get("valve_open", False))

        pump_speed_x10 = clamp_int(pump_speed_x10, 0, 1000)

        return PLCImage(
            shield_enable=True,
            seq_id=seq_id,
            heartbeat=self.heartbeat_counter,
            valid=decision in (DECISION_ALLOW, DECISION_DOWNGRADE),
            decision_code=decision,
            risk_score=clamp_int(int(risk_score), 0, 100),
            pump_speed_cmd_x10=pump_speed_x10,
            valve_open_cmd=valve_open,
            fallback_required=decision == DECISION_FALLBACK,
            safe_stop_required=decision == DECISION_BLOCK,
            reason_code=reason,
        )

    def _emit(
        self,
        command: Dict[str, Any],
        decision: int,
        reason: int,
        risk_score: int,
        safe_command: Optional[Dict[str, Any]],
        now: float,
    ) -> None:
        """Publish validated command, PLC image, alerts, and metrics."""
        if decision == DECISION_ALLOW:
            self.total_allowed += 1
        elif decision == DECISION_DOWNGRADE:
            self.total_downgraded += 1
        elif decision == DECISION_FALLBACK:
            self.total_fallback += 1
        else:
            self.total_blocked += 1

        plc_image = self._build_plc_image(command, decision, reason, risk_score, safe_command)

        validated_payload = {
            "timestamp": now,
            "decision": DECISION_NAMES[decision],
            "decision_code": decision,
            "reason": REASON_NAMES.get(reason, "unknown"),
            "reason_code": reason,
            "risk_score": risk_score,
            "safe_command": safe_command,
            "plc_image": asdict(plc_image),
        }

        self.client.publish(TOPIC_VALIDATED, json.dumps(validated_payload), qos=1, retain=False)
        self.client.publish(TOPIC_PLC_IMAGE, json.dumps(asdict(plc_image)), qos=1, retain=False)

        if decision != DECISION_ALLOW:
            alert = {
                "timestamp": now,
                "decision": DECISION_NAMES[decision],
                "reason": REASON_NAMES.get(reason, "unknown"),
                "risk_score": risk_score,
                "sequence_id": command.get("sequence_id", 0) if isinstance(command, dict) else 0,
            }
            self.client.publish(TOPIC_ALERTS, json.dumps(alert), qos=1, retain=False)

        metrics = {
            "timestamp": now,
            "total_seen": self.total_seen,
            "total_allowed": self.total_allowed,
            "total_downgraded": self.total_downgraded,
            "total_fallback": self.total_fallback,
            "total_blocked": self.total_blocked,
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
        }
        self.client.publish(TOPIC_METRICS, json.dumps(metrics), qos=0, retain=False)

    def emit_shutdown_image(self) -> None:
        """Publish a final fail-safe image before clean shutdown."""
        self.heartbeat_counter = (self.heartbeat_counter + 1) % 2147483647

        plc_image = PLCImage(
            shield_enable=False,
            seq_id=int(self.last_sequence_id or 0),
            heartbeat=self.heartbeat_counter,
            valid=False,
            decision_code=DECISION_BLOCK,
            risk_score=100,
            pump_speed_cmd_x10=0,
            valve_open_cmd=False,
            fallback_required=False,
            safe_stop_required=True,
            reason_code=REASON_INTERNAL_ERROR,
        )

        shutdown_payload = {
            "timestamp": time.time(),
            "event": "software_shield_shutdown",
            "decision": DECISION_NAMES[DECISION_BLOCK],
            "decision_code": DECISION_BLOCK,
            "reason": "operator_shutdown",
            "reason_code": REASON_INTERNAL_ERROR,
            "risk_score": 100,
            "plc_image": asdict(plc_image),
        }

        self.client.publish(TOPIC_PLC_IMAGE, json.dumps(asdict(plc_image)), qos=1, retain=False)
        self.client.publish(TOPIC_VALIDATED, json.dumps(shutdown_payload), qos=1, retain=False)
        self.client.publish(TOPIC_ALERTS, json.dumps(shutdown_payload), qos=1, retain=False)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="OT-Aegis safety-profile MQTT Software Shield")

    parser.add_argument("--broker", default="localhost", help="MQTT broker hostname or IP address.")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker TCP port.")
    parser.add_argument("--maintenance", action="store_true", help="Enable maintenance mode.")
    parser.add_argument("--cyber-alert", action="store_true", help="Enable cyber alert context.")

    return parser.parse_args()


def is_connected_reason_code_success(reason_code: Any) -> bool:
    """Return True if a Paho MQTT connection reason code indicates success."""
    if hasattr(reason_code, "is_failure"):
        return not reason_code.is_failure

    return int(reason_code) == 0


def main() -> None:
    """Program entry point."""
    args = parse_args()

    config = ShieldConfig(
        maintenance_mode=args.maintenance,
        cyber_alert_active=args.cyber_alert,
    )

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    shield = SoftwareShield(client, config)

    def on_connect(
        client: mqtt.Client,
        _userdata: Any,
        _flags: Any,
        reason_code: Any,
        _properties: Any = None,
    ) -> None:
        """Subscribe to AI command topic after a successful broker connection."""
        if is_connected_reason_code_success(reason_code):
            client.subscribe(TOPIC_AI_COMMANDS, qos=1)
            print(f"Connected to MQTT broker. Subscribed to {TOPIC_AI_COMMANDS}")
        else:
            print(f"MQTT connection failed: {reason_code}")

    client.on_connect = on_connect
    client.on_message = shield.on_message

    try:
        client.connect(args.broker, args.port, keepalive=30)
        print("OT-Aegis Software Shield started. Press CTRL+C to stop cleanly.")
        client.loop_forever()

    except KeyboardInterrupt:
        print("\nCTRL+C received. Publishing fail-safe shutdown image...")
        try:
            shield.emit_shutdown_image()
            client.loop(timeout=1.0)
            time.sleep(0.2)
        except Exception as exc:
            print(f"Warning: could not publish shutdown image: {exc}")

    finally:
        try:
            client.loop_stop()
        except Exception:
            pass

        try:
            client.disconnect()
        except Exception:
            pass

        print("Software Shield stopped cleanly.")


if __name__ == "__main__":
    main()
