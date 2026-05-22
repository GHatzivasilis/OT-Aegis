#!/usr/bin/env python3
"""
PLC-aware MQTT Monitor for the OT-Aegis prototype.

Purpose
-------
This utility subscribes to the MQTT topics used by the OT-Aegis demo and
prints the messages exchanged between:

    AI Agent  ->  Software Shield  ->  PLC-facing command image

It is intended for demonstration, debugging, and experiment observation. In
particular, it prints the `ics/shield/plc_image` topic in a compact
PLC-oriented format so that the command image can be inspected easily.

Subscribed topics
-----------------
- ics/ai_agent/commands
    Raw AI-agent commands published by the AI emulator.

- ics/ai_agent/status
    Optional AI-agent status/health messages.

- ics/shield/validated_commands
    Rich Software Shield output containing the shield decision, reason,
    risk score, safe command, and embedded PLC image.

- ics/shield/plc_image
    Flat PLC/Safety-PLC-facing command image. This is the most important
    topic for observing what would be transferred to a PLC via a bridge
    such as OPC UA, Modbus TCP, or Siemens S7 DB writes.

- ics/shield/alerts
    Alert messages emitted when the Software Shield does not fully allow
    a command.

- ics/shield/metrics
    Shield and host telemetry metrics.

Graceful shutdown
-----------------
The program handles CTRL+C cleanly. It stops the MQTT loop, disconnects from
Mosquitto, and exits without printing a Python traceback.

Example
-------
    python mqtt_monitor_plc_documented.py

Optional arguments:
    python mqtt_monitor_plc_documented.py --broker localhost --port 1883
"""

import argparse
import json
from typing import Any, Dict, Iterable, Optional

import paho.mqtt.client as mqtt


DEFAULT_BROKER = "localhost"
DEFAULT_PORT = 1883

TOPIC_AI_COMMANDS = "ics/ai_agent/commands"
TOPIC_AI_STATUS = "ics/ai_agent/status"
TOPIC_VALIDATED = "ics/shield/validated_commands"
TOPIC_PLC_IMAGE = "ics/shield/plc_image"
TOPIC_ALERTS = "ics/shield/alerts"
TOPIC_METRICS = "ics/shield/metrics"

TOPICS = [
    TOPIC_AI_COMMANDS,
    TOPIC_AI_STATUS,
    TOPIC_VALIDATED,
    TOPIC_PLC_IMAGE,
    TOPIC_ALERTS,
    TOPIC_METRICS,
]


DECISION_NAMES = {
    1: "ALLOW",
    2: "DOWNGRADE",
    3: "FALLBACK_REQUEST",
    4: "BLOCK",
}

REASON_NAMES = {
    0: "NONE",
    10: "MALFORMED",
    11: "LOW_CONFIDENCE",
    12: "STALE",
    13: "REPLAY",
    14: "SOFT_BOUND_VIOLATION",
    15: "RATE_OF_CHANGE",
    16: "PROCESS_IMPLAUSIBLE",
    17: "DOS_DETECTED",
    18: "MAINTENANCE_LOCKOUT",
    19: "CYBER_ALERT",
    99: "INTERNAL_ERROR",
}


def decode_payload(raw_payload: bytes) -> Any:
    """
    Decode an MQTT payload.

    The shield and agent normally publish JSON. If a non-JSON payload is
    received, this function returns a UTF-8 string instead of raising an
    exception. This makes the monitor robust during experiments where malformed
    test payloads may be intentionally injected.

    Args:
        raw_payload: Raw MQTT payload bytes.

    Returns:
        A decoded JSON object, usually a dict, or a decoded string.
    """
    text = raw_payload.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def pretty_json(payload: Any) -> str:
    """
    Convert a payload into a readable string representation.

    Args:
        payload: Decoded payload object.

    Returns:
        Pretty-printed JSON for dictionaries/lists, otherwise plain string.
    """
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, indent=2, sort_keys=True)
    return str(payload)


def get_int(payload: Dict[str, Any], key: str, default: int = 0) -> int:
    """
    Safely extract an integer value from a dictionary.

    This avoids monitor crashes if a malformed test message contains an
    unexpected type.
    """
    try:
        return int(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def get_bool(payload: Dict[str, Any], key: str, default: bool = False) -> bool:
    """
    Safely extract a Boolean value from a dictionary.
    """
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def format_plc_image(payload: Dict[str, Any]) -> str:
    """
    Format the PLC-facing command image in a compact engineering view.

    The PLC image is deliberately flat and numeric so that a PLC bridge can map
    it to tags/registers without complex parsing. This formatter shows both the
    raw integer fields and the engineering interpretation of selected values.

    Args:
        payload: Decoded PLC image dictionary from `ics/shield/plc_image`.

    Returns:
        Multi-line formatted text.
    """
    decision_code = get_int(payload, "decision_code")
    reason_code = get_int(payload, "reason_code")
    pump_speed_x10 = get_int(payload, "pump_speed_cmd_x10")
    pump_speed_percent = pump_speed_x10 / 10.0

    lines = [
        "PLC IMAGE",
        f"  shield_enable       : {get_bool(payload, 'shield_enable')}",
        f"  seq_id              : {get_int(payload, 'seq_id')}",
        f"  heartbeat           : {get_int(payload, 'heartbeat')}",
        f"  valid               : {get_bool(payload, 'valid')}",
        f"  decision_code       : {decision_code} ({DECISION_NAMES.get(decision_code, 'UNKNOWN')})",
        f"  reason_code         : {reason_code} ({REASON_NAMES.get(reason_code, 'UNKNOWN')})",
        f"  risk_score          : {get_int(payload, 'risk_score')}",
        f"  pump_speed_cmd_x10  : {pump_speed_x10} ({pump_speed_percent:.1f}%)",
        f"  valve_open_cmd      : {get_bool(payload, 'valve_open_cmd')}",
        f"  fallback_required   : {get_bool(payload, 'fallback_required')}",
        f"  safe_stop_required  : {get_bool(payload, 'safe_stop_required')}",
    ]
    return "\n".join(lines)


def print_message(topic: str, payload: Any) -> None:
    """
    Print an MQTT message using topic-specific formatting.

    Args:
        topic: MQTT topic name.
        payload: Decoded payload.
    """
    print("\n" + "=" * 88)
    print(f"TOPIC: {topic}")

    if topic == TOPIC_PLC_IMAGE and isinstance(payload, dict):
        print(format_plc_image(payload))
    else:
        print(pretty_json(payload))


def subscribe_topics(client: mqtt.Client, topics: Iterable[str]) -> None:
    """
    Subscribe the MQTT client to all monitor topics.

    Args:
        client: Connected MQTT client.
        topics: Iterable of topic strings.
    """
    for topic in topics:
        client.subscribe(topic, qos=1)
        print(f"[SUBSCRIBED] {topic}")


def on_connect(client: mqtt.Client, _userdata: Any, _flags: Any, reason_code: Any, _properties: Any = None) -> None:
    """
    MQTT connection callback.

    This implementation supports Paho MQTT callback API v2, where the result is
    represented by a ReasonCode object. It also tolerates older integer-style
    return codes.
    """
    if hasattr(reason_code, "is_failure"):
        connected = not reason_code.is_failure
        rc_text = str(reason_code)
    else:
        connected = int(reason_code) == 0
        rc_text = str(reason_code)

    print(f"[INFO] Connected result={rc_text}")

    if connected:
        subscribe_topics(client, TOPICS)
    else:
        print("[ERROR] MQTT connection was not accepted by the broker.")


def on_disconnect(_client: mqtt.Client, _userdata: Any, disconnect_flags: Any, reason_code: Any, _properties: Any = None) -> None:
    """
    MQTT disconnection callback.

    The callback is mainly informational. Graceful shutdown is performed in
    `main()`.
    """
    print(f"[INFO] Disconnected reason={reason_code}")


def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
    """
    MQTT message callback.

    Args:
        msg: Incoming MQTT message including topic and payload.
    """
    payload = decode_payload(msg.payload)
    print_message(msg.topic, payload)


def build_client(client_id: Optional[str] = "ot-aegis-monitor") -> mqtt.Client:
    """
    Build and configure a Paho MQTT client.

    Args:
        client_id: Optional MQTT client identifier.

    Returns:
        Configured MQTT client.
    """
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
    )
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    return client


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="PLC-aware MQTT monitor for OT-Aegis")
    parser.add_argument("--broker", default=DEFAULT_BROKER, help="MQTT broker hostname or IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="MQTT broker TCP port")
    parser.add_argument("--client-id", default="ot-aegis-monitor", help="MQTT client identifier")
    return parser.parse_args()


def main() -> None:
    """
    Program entry point.

    The monitor runs until interrupted with CTRL+C. On interruption, it stops the
    MQTT network loop and disconnects cleanly so that the demo terminates without
    an exception traceback.
    """
    args = parse_args()
    client = build_client(client_id=args.client_id)

    try:
        print(f"[INFO] Connecting to MQTT broker {args.broker}:{args.port} ...")
        client.connect(args.broker, args.port, keepalive=30)
        print("[INFO] MQTT monitor running. Press CTRL+C to stop.")
        client.loop_forever()

    except KeyboardInterrupt:
        print("\n[INFO] CTRL+C received. Stopping MQTT monitor...")

    finally:
        try:
            client.loop_stop()
        except Exception:
            pass

        try:
            client.disconnect()
        except Exception:
            pass

        print("[INFO] MQTT monitor stopped cleanly.")


if __name__ == "__main__":
    main()
