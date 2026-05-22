"""
MQTT AI Agent Emulator Publisher

This service emulates an AI agent that continuously monitors an ICS process
and publishes proposed control commands to an MQTT broker.

The generated command depends on the selected agent behavior:
    - normal: valid commands, high confidence
    - faulty: unstable or low-confidence commands
    - compromised: clearly unsafe malicious commands
    - stealthy: gradual malicious escalation within nominal bounds
    - stale: replay-like old commands
    - dos_flood: high-rate command publication for DoS experiments

MQTT topic:
    ics/ai_agent/commands

The Software Shield subscribes to this topic, validates the commands,
and publishes approved/fallback decisions to:
    ics/shield/validated_commands
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

import psutil
import paho.mqtt.client as mqtt


class AgentBehavior(str, Enum):
    """Supported runtime behavior modes for the AI agent emulator."""

    NORMAL = "normal"
    FAULTY = "faulty"
    COMPROMISED = "compromised"
    STEALTHY = "stealthy"
    STALE = "stale"
    DOS_FLOOD = "dos_flood"


@dataclass
class AgentConfig:
    """Configuration parameters for the AI agent emulator."""

    agent_id: str = "ai-agent-1"
    pump_min: float = 0.0
    pump_max: float = 80.0
    normal_confidence_min: float = 0.85
    faulty_confidence_max: float = 0.55
    malicious_pump_value: float = 120.0


class AIAgentEmulator:
    """
    Parameterized AI agent emulator.

    The emulator produces ICS control recommendations containing:
        - pump speed
        - valve state
        - confidence score
        - heartbeat
        - sequence ID
        - timestamp

    The behavior can be changed by setting self.behavior.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.behavior = AgentBehavior.NORMAL
        self.sequence_id = 0
        self.heartbeat = False
        self.last_pump_speed = 40.0
        self.last_command: Optional[Dict[str, Any]] = None
        self.started_at = time.time()
        self.commands_generated = 0

    def set_behavior(self, behavior: AgentBehavior | str) -> None:
        """Set the current behavior mode."""
        self.behavior = AgentBehavior(behavior)

    def generate_command(self) -> Dict[str, Any]:
        """Generate one AI command according to the active behavior mode."""
        if self.behavior == AgentBehavior.NORMAL:
            command = self._normal()
        elif self.behavior == AgentBehavior.FAULTY:
            command = self._faulty()
        elif self.behavior == AgentBehavior.COMPROMISED:
            command = self._compromised()
        elif self.behavior == AgentBehavior.STEALTHY:
            command = self._stealthy()
        elif self.behavior == AgentBehavior.STALE:
            command = self._stale()
        elif self.behavior == AgentBehavior.DOS_FLOOD:
            command = self._dos_flood()
        else:
            raise ValueError(f"Unsupported behavior: {self.behavior}")

        self.commands_generated += 1
        self.last_command = dict(command)
        return command

    def _base_command(
        self,
        pump_speed: float,
        valve_open: bool,
        confidence: float,
        command_valid: bool,
        explanation: str,
        advance_sequence: bool = True,
        toggle_heartbeat: bool = True,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Build a command message.

        Args:
            pump_speed: Proposed pump speed percentage.
            valve_open: Proposed valve state.
            confidence: AI confidence score.
            command_valid: Whether the AI considers the command internally valid.
            explanation: Human-readable explanation.
            advance_sequence: If False, simulates replay behavior.
            toggle_heartbeat: If False, simulates heartbeat malfunction.
            timestamp: Optional custom timestamp, useful for stale/replay attacks.
        """
        if advance_sequence:
            self.sequence_id += 1

        if toggle_heartbeat:
            self.heartbeat = not self.heartbeat

        self.last_pump_speed = pump_speed

        return {
            "timestamp": timestamp if timestamp is not None else time.time(),
            "agent_id": self.config.agent_id,
            "behavior": self.behavior.value,
            "sequence_id": self.sequence_id,
            "heartbeat": self.heartbeat,
            "command_valid": command_valid,
            "pump_speed": round(pump_speed, 2),
            "valve_open": valve_open,
            "confidence": round(confidence, 3),
            "explanation": explanation,
        }

    def _normal(self) -> Dict[str, Any]:
        """Generate normal high-confidence commands."""
        return self._base_command(
            pump_speed=random.uniform(35.0, 55.0),
            valve_open=True,
            confidence=random.uniform(self.config.normal_confidence_min, 0.99),
            command_valid=True,
            explanation="Normal demand-based pump optimization.",
        )

    def _faulty(self) -> Dict[str, Any]:
        """Generate faulty, unstable, or low-confidence commands."""
        pump = random.choice(
            [
                random.uniform(0.0, 20.0),
                random.uniform(70.0, 85.0),
                self.last_pump_speed + random.uniform(-40.0, 40.0),
            ]
        )

        return self._base_command(
            pump_speed=pump,
            valve_open=random.choice([True, False]),
            confidence=random.uniform(0.1, self.config.faulty_confidence_max),
            command_valid=random.choice([True, False]),
            explanation="Faulty output: low confidence, unstable, or invalid command.",
        )

    def _compromised(self) -> Dict[str, Any]:
        """Generate clearly malicious unsafe commands."""
        return self._base_command(
            pump_speed=self.config.malicious_pump_value,
            valve_open=False,
            confidence=0.98,
            command_valid=True,
            explanation="Compromised behavior: high pump speed with closed valve.",
        )

    def _stealthy(self) -> Dict[str, Any]:
        """Generate gradual malicious escalation while staying within hard bounds."""
        pump = min(self.last_pump_speed + random.uniform(2.0, 5.0), self.config.pump_max)

        return self._base_command(
            pump_speed=pump,
            valve_open=True,
            confidence=random.uniform(0.80, 0.95),
            command_valid=True,
            explanation="Stealthy behavior: gradual increase within nominal bounds.",
        )

    def _stale(self) -> Dict[str, Any]:
        """
        Generate stale/replay-like commands.

        The sequence ID is not advanced and the timestamp is intentionally old.
        """
        if self.last_command is not None:
            stale = dict(self.last_command)
            stale["behavior"] = self.behavior.value
            stale["timestamp"] = time.time() - 5.0
            stale["explanation"] = "Stale/replayed command with old timestamp."
            return stale

        return self._base_command(
            pump_speed=40.0,
            valve_open=True,
            confidence=0.90,
            command_valid=True,
            explanation="Initial stale command seed.",
            timestamp=time.time() - 5.0,
            advance_sequence=False,
        )

    def _dos_flood(self) -> Dict[str, Any]:
        """
        Generate valid-looking commands for DoS flooding experiments.

        The actual flooding rate is controlled by the publishing loop period.
        """
        return self._base_command(
            pump_speed=random.uniform(40.0, 65.0),
            valve_open=True,
            confidence=random.uniform(0.80, 0.95),
            command_valid=True,
            explanation="DoS flood behavior: high-rate valid-looking command.",
        )

    def metrics(self) -> Dict[str, Any]:
        """Return lightweight runtime metrics for local logging."""
        proc = psutil.Process()

        return {
            "agent_id": self.config.agent_id,
            "behavior": self.behavior.value,
            "uptime_s": round(time.time() - self.started_at, 3),
            "commands_generated": self.commands_generated,
            "cpu_percent": proc.cpu_percent(interval=0.0),
            "memory_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 3),
        }


class MQTTAgentPublisher:
    """
    MQTT publisher wrapper for the AI Agent Emulator.

    Publishes:
        - raw AI commands to ics/ai_agent/commands
        - optional status metrics to ics/ai_agent/status
    """

    def __init__(
        self,
        agent: AIAgentEmulator,
        broker_host: str,
        broker_port: int,
        command_topic: str,
        status_topic: str,
        qos: int = 1,
    ):
        self.agent = agent
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.command_topic = command_topic
        self.status_topic = status_topic
        self.qos = qos

        self.client = mqtt.Client(client_id=f"{agent.config.agent_id}-publisher")
        self.running = False

    def connect(self) -> None:
        """Connect to the MQTT broker."""
        self.client.connect(self.broker_host, self.broker_port, keepalive=30)
        self.client.loop_start()

    def disconnect(self) -> None:
        """Disconnect gracefully from the MQTT broker."""
        self.client.loop_stop()
        self.client.disconnect()

    def publish_command(self) -> Dict[str, Any]:
        """Generate and publish one command message."""
        command = self.agent.generate_command()
        payload = json.dumps(command)

        result = self.client.publish(self.command_topic, payload=payload, qos=self.qos)
        result.wait_for_publish()

        return command

    def publish_status(self) -> None:
        """Publish local runtime metrics."""
        status_payload = json.dumps(self.agent.metrics())
        self.client.publish(self.status_topic, payload=status_payload, qos=0)

    def run(self, period_s: float, status_period_s: float = 5.0) -> None:
        """
        Run continuous command publication.

        Args:
            period_s: Time between command publications.
            status_period_s: Time between status metric publications.
        """
        self.running = True
        last_status = 0.0

        while self.running:
            command = self.publish_command()

            print(
                f"[PUBLISH] topic={self.command_topic} "
                f"behavior={command['behavior']} "
                f"seq={command['sequence_id']} "
                f"pump={command['pump_speed']} "
                f"valve={command['valve_open']} "
                f"conf={command['confidence']}"
            )

            now = time.time()
            if now - last_status >= status_period_s:
                self.publish_status()
                last_status = now

            time.sleep(period_s)

    def stop(self) -> None:
        """Stop the continuous publisher loop."""
        self.running = False


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="MQTT AI Agent Emulator Publisher")

    parser.add_argument("--broker-host", default="localhost", help="MQTT broker host")
    parser.add_argument("--broker-port", type=int, default=1883, help="MQTT broker port")
    parser.add_argument("--agent-id", default="ai-agent-1", help="Agent identifier")
    parser.add_argument(
        "--behavior",
        default="normal",
        choices=[b.value for b in AgentBehavior],
        help="Initial agent behavior",
    )
    parser.add_argument(
        "--period",
        type=float,
        default=1.0,
        help="Command publication period in seconds",
    )
    parser.add_argument(
        "--command-topic",
        default="ics/ai_agent/commands",
        help="MQTT topic for AI commands",
    )
    parser.add_argument(
        "--status-topic",
        default="ics/ai_agent/status",
        help="MQTT topic for AI agent status messages",
    )
    parser.add_argument("--qos", type=int, default=1, choices=[0, 1, 2], help="MQTT QoS")

    return parser.parse_args()


def main() -> None:
    """Program entry point."""
    args = parse_args()

    agent = AIAgentEmulator(AgentConfig(agent_id=args.agent_id))
    agent.set_behavior(args.behavior)

    publisher = MQTTAgentPublisher(
        agent=agent,
        broker_host=args.broker_host,
        broker_port=args.broker_port,
        command_topic=args.command_topic,
        status_topic=args.status_topic,
        qos=args.qos,
    )

    def handle_shutdown(signum, frame):
        print("\n[INFO] Shutdown requested.")
        publisher.stop()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    print(
        f"[INFO] Starting MQTT AI Agent Publisher "
        f"broker={args.broker_host}:{args.broker_port} "
        f"behavior={args.behavior} "
        f"period={args.period}s"
    )

    try:
        publisher.connect()
        publisher.run(period_s=args.period)
    except KeyboardInterrupt:
        publisher.stop()
    finally:
        publisher.disconnect()
        print("[INFO] Publisher stopped.")


if __name__ == "__main__":
    main()