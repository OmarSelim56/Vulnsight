import warnings
from pathlib import Path

from src.api.client import DashboardReporter
from src.core.settings import settings
from src.detection.collector import TrafficCollector
from src.detection.engine import InferenceEngine

warnings.filterwarnings("ignore", category=UserWarning)

_PROJECT_ROOT = Path(__file__).parent


def start_vulnsight(api_base_url=settings.api_base_url):
    # 1. Initialize core services
    engine = InferenceEngine(
        model_path=str(_PROJECT_ROOT / "model" / "vulnsight_cnn_bilstm.pth"),
        scaler_path=str(_PROJECT_ROOT / "model" / "scaler.pkl"),
        use_shap=True,
    )
    collector = TrafficCollector()
    reporter = DashboardReporter(base_url=api_base_url)

    print("\n" + "=" * 50)
    print("VULNSIGHT NIDS IS LIVE")
    print("Status: Monitoring detected active interface traffic")
    print(f"Posting alerts to: {api_base_url}")
    print("=" * 50 + "\n")

    try:
        # 2. Continuous loop: consume flows -> infer -> post to API
        for features, metadata in collector.get_flows():
            prediction, confidence = engine.process_flow(features)

            if prediction is None:
                continue
            else:
                shap_top_features = []
                if prediction == 1:
                    shap_top_features = engine.explain_latest_window(top_k=5)

                reporter.post_alert(
                    metadata=metadata,
                    prediction=prediction,
                    confidence=confidence,
                    shap_top_features=shap_top_features,
                )

    except KeyboardInterrupt:
        report = reporter.generate_report()
        if report:
            print("\n\nFinal report generated and available via API.")
        print("\nVulnSight shutting down safely...")

if __name__ == "__main__":
    start_vulnsight()