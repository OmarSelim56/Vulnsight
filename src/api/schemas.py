from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ShapInsight(BaseModel):
    feature: str
    impact: float
    direction: str


class AlertPayload(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: Optional[int] = None
    dst_port: Optional[int] = None
    interface: Optional[str] = None
    prediction: int
    label: str
    confidence: float
    confidence_level: str
    severity: str
    triage_action: str
    is_malicious: bool
    attack_type: Optional[str] = None
    # "signature" = deterministic rule hit (high precision, known coverage)
    # "model"     = CNN-BiLSTM ML prediction (probabilistic, may catch novel)
    # None        = legacy/imported alert with unknown provenance
    detection_source: Optional[str] = None
    # Free-text explanation of WHY a rule fired (signature alerts only).
    detection_reason: Optional[str] = None
    dedup_count: int = 1
    shap_top_features: List[ShapInsight] = Field(default_factory=list)


class ReportPayload(BaseModel):
    generated_at: datetime
    total_events: int
    malicious_events: int
    benign_events: int
    malicious_ratio: float
    severity_breakdown: Dict[str, int]
    top_targets: Dict[str, int]
