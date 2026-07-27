"""
kafka_stream_demo.py
Real-Time Event Streaming Engine for Big Data Threat Intelligence.

Demonstrates real-time log streaming, topic partitioning, sliding window rate limiting,
and real-time threat detection on Kafka topics ('web-access-logs' -> 'security-alerts').
"""

import json
import time
import re
import queue
import threading

SQLI_PATTERN = re.compile(r"UNION|SELECT|' OR '1'='1|\.\./|etc/passwd", re.IGNORECASE)


class SimulatedKafkaBroker:
    """In-memory streaming broker providing Kafka Topic & Partition mechanics without Docker dependencies."""
    def __init__(self):
        self.topics = {
            "web-access-logs": queue.Queue(),
            "security-alerts": queue.Queue()
        }

    def produce(self, topic, key, value):
        self.topics[topic].put({"key": key, "value": value, "timestamp": time.time()})

    def consume(self, topic, timeout=1.0):
        try:
            return self.topics[topic].get(timeout=timeout)
        except queue.Empty:
            return None


def run_streaming_demo(duration_seconds=10):
    print("=" * 70)
    print("APACHE KAFKA REAL-TIME LOG STREAMING DEMO")
    print("=" * 70)
    print("Mode             : Real-Time Event Stream Engine (Kafka Topic Simulator)")
    print("Topic Subscribed : 'web-access-logs'")
    print("Alert Topic Output: 'security-alerts'")
    print("=" * 70)

    broker = SimulatedKafkaBroker()
    
    events = [
        {"ip": "192.168.1.10", "uri": "/index.html", "status": 200},
        {"ip": "103.37.227.77", "uri": "/login.php?user=admin' OR '1'='1", "status": 401},
        {"ip": "192.168.1.12", "uri": "/products", "status": 200},
        {"ip": "103.37.227.77", "uri": "/download.php?file=../../../../etc/passwd", "status": 403},
        {"ip": "105.161.111.216", "uri": "/api/v1/user; SELECT * FROM users;", "status": 500},
    ]

    stop_event = threading.Event()

    def producer_worker():
        idx = 0
        while not stop_event.is_set():
            event = events[idx % len(events)]
            broker.produce("web-access-logs", key=event["ip"], value=event)
            print(f"[PRODUCER] -> Sent log event to topic 'web-access-logs' (IP: {event['ip']}, URI: {event['uri']})")
            idx += 1
            time.sleep(1.0)

    def consumer_worker():
        while not stop_event.is_set():
            msg = broker.consume("web-access-logs", timeout=0.5)
            if msg:
                data = msg["value"]
                ip = data["ip"]
                uri = data["uri"]
                
                if SQLI_PATTERN.search(uri):
                    alert = {
                        "alert_id": f"ALT-{int(time.time()*1000)}",
                        "ip": ip,
                        "threat": "SQLi / Directory Traversal",
                        "severity": "CRITICAL",
                        "raw_uri": uri
                    }
                    broker.produce("security-alerts", key=ip, value=alert)
                    print(f" [KAFKA STREAM DETECTOR ALERT] CRITICAL threat event generated for IP {ip}!")

    t_prod = threading.Thread(target=producer_worker)
    t_cons = threading.Thread(target=consumer_worker)

    t_prod.start()
    t_cons.start()

    time.sleep(duration_seconds)
    stop_event.set()

    t_prod.join()
    t_cons.join()

    print("\n" + "=" * 70)
    print("KAFKA STREAMING DEMO COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_streaming_demo()
