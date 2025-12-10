"""
Timeline Builder
Combines outputs from other modules into a chronological event list.
"""

import os
import json

def load_events(folder="analysis_output"):
    events = []

    for file in os.listdir(folder):
        if file.endswith(".json"):
            with open(os.path.join(folder, file)) as f:
                data = json.load(f)
                events.extend(data)

    return sorted(events, key=lambda e: e["timestamp"])

def print_timeline(events):
    print("Event Timeline:")
    for event in events:
        print(f"{event['timestamp']} - {event['type']}: {event['details']}")

if __name__ == "__main__":
    events = load_events()
    print_timeline(events)
