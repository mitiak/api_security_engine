import json
from typing import List

from kafka import KafkaProducer  # type: ignore

from api_security_engine.lib.alert_handler import AlertHandler
from api_security_engine.lib.models import ThreatSeverity, SecurityEngineAlert


class KafkaAlertHandler(AlertHandler):
    def __init__(
            self,
            alert_severity: ThreatSeverity,
            bootstrap_servers: str,
            topics: List[str],
    ) -> None:
        """
        The function initializes a KafkaProducer object with the given configuration and topics.

        :param alert_severity: The `alert_severity` parameter is of type `ThreatSeverity`. It is used to specify the
        severity level of the alert
        :type alert_severity: ThreatSeverity

        :param bootstrap_servers: Specifies the Kafka broker addresses to connect to
        :type bootstrap_servers: str

        :param topics: The `topics` parameter is a list of strings that represents the topics to which the Kafka producer
        will send messages. Each string in the list represents a topic name
        :type topics: List[str]
        """
        super().__init__(alert_severity)

        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda x: json.dumps(x).encode("utf-8")
        )

        self.topics = topics

    async def handle_alert(self, alert: SecurityEngineAlert) -> None:
        """
        The function handles a security engine alert by sending it to multiple topics using a producer and then flushing the
        producer to ensure all messages are sent.

        :param alert: The `alert` parameter is of type `SecurityEngineAlert`. It represents an alert generated by a security
        engine
        :type alert: SecurityEngineAlert
        """
        for topic in self.topics:
            self.producer.send(topic, value=alert)

        # Close the producer to ensure all messages are sent
        self.producer.flush()
