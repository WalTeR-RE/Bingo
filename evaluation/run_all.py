import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SCRIPTS = [
    "speech_recognition_performance",
    "intent_routing_accuracy",
    "user_interaction_performance",
    "xgboost_classification_performance",
    "threat_threshold_evaluation",
    "network_interception_performance",
    "target_discovery_performance",
    "swarm_execution_evaluation",
    "vuln_detection_results",
    "false_positive_analysis",
]


def main():
    for name in SCRIPTS:
        module = importlib.import_module(name)
        module.main()
        print()
    print(f"All charts written to {Path(__file__).parent / 'charts'}")


if __name__ == "__main__":
    main()
