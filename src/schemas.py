"""
Pydantic schemas for request validation, incidents, analytics, and telemetry serialization.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ConnectionFeatures(BaseModel):
    """
    40-feature schema representing a single network connection record in NSL-KDD format.
    """
    # Categorical features
    protocol_type: str = Field(default="tcp", description="Transport layer protocol: tcp, udp, or icmp")
    service: str = Field(default="http", description="Network service on destination host")
    flag: str = Field(default="SF", description="Normal or error status flag of connection")

    # Basic connection features
    duration: float = Field(default=0.0, ge=0.0, description="Length of connection in seconds")
    src_bytes: float = Field(default=215.0, ge=0.0, description="Number of data bytes from source to destination")
    dst_bytes: float = Field(default=450.0, ge=0.0, description="Number of data bytes from destination to source")
    land: int = Field(default=0, ge=0, le=1, description="1 if connection is from/to the same host/port")
    wrong_fragment: float = Field(default=0.0, ge=0.0, description="Number of wrong fragments")
    urgent: float = Field(default=0.0, ge=0.0, description="Number of urgent packets")

    # Content / Authentication features
    hot: float = Field(default=0.0, ge=0.0, description="Number of hot indicators")
    num_failed_logins: float = Field(default=0.0, ge=0.0, description="Number of failed login attempts")
    logged_in: int = Field(default=1, ge=0, le=1, description="1 if successfully logged in")
    num_compromised: float = Field(default=0.0, ge=0.0, description="Number of compromised conditions")
    root_shell: int = Field(default=0, ge=0, le=1, description="1 if root shell is obtained")
    su_attempted: int = Field(default=0, ge=0, le=2, description="1 if 'su root' command attempted")
    num_root: float = Field(default=0.0, ge=0.0, description="Number of root accesses")
    num_file_creations: float = Field(default=0.0, ge=0.0, description="Number of file creation operations")
    num_shells: float = Field(default=0.0, ge=0.0, description="Number of shell prompts")
    num_access_files: float = Field(default=0.0, ge=0.0, description="Number of operations on access control files")
    is_host_login: int = Field(default=0, ge=0, le=1, description="1 if login belongs to the host list")
    is_guest_login: int = Field(default=0, ge=0, le=1, description="1 if login is a guest account")

    # Time-based traffic statistics
    count: float = Field(default=1.0, ge=0.0, description="Number of connections to the same host in past 2 seconds")
    srv_count: float = Field(default=1.0, ge=0.0, description="Number of connections to the same service in past 2 seconds")
    serror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections that have SYN errors")
    srv_serror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to same service with SYN errors")
    rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections that have REJ errors")
    srv_rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to same service with REJ errors")
    same_srv_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="% of connections to the same service")
    diff_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to different services")
    srv_diff_host_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to different hosts")

    # Host-based traffic statistics
    dst_host_count: float = Field(default=255.0, ge=0.0, description="Count of connections having same destination host IP")
    dst_host_srv_count: float = Field(default=255.0, ge=0.0, description="Count of connections having same destination host IP and service")
    dst_host_same_srv_rate: float = Field(default=1.0, ge=0.0, le=1.0, description="% of connections to same destination host and same service")
    dst_host_diff_srv_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to same destination host and different service")
    dst_host_same_src_port_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to same port on same host")
    dst_host_srv_diff_host_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections to same service on different destination hosts")
    dst_host_serror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections with SYN errors to destination host")
    dst_host_srv_serror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections with SYN errors to same service on destination host")
    dst_host_rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections with REJ errors to destination host")
    dst_host_srv_rerror_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="% of connections with REJ errors to same service on destination host")


class Stage1Output(BaseModel):
    attack_probability: float
    threshold: float
    decision: str  # "Normal" or "Attack"
    is_attack: bool


class Stage2Output(BaseModel):
    attack_family: Optional[str] = None
    description: Optional[str] = None
    probabilities: Optional[Dict[str, float]] = None


class PredictionResponse(BaseModel):
    success: bool = True
    final_prediction: str  # "Normal", "DoS", "Probe", "R2L", or "U2R"
    is_attack: bool
    alert_severity: str    # "low", "medium", "high", "critical"
    stage1: Stage1Output
    stage2: Optional[Stage2Output] = None
    timestamp: str
    sample_id: Optional[str] = None
    incident_id: Optional[str] = None
    latency_ms: Optional[float] = None


class PresetResponse(BaseModel):
    id: str
    name: str
    family: str
    label: str
    description: str
    data: Dict[str, Any]


class ModelInfoResponse(BaseModel):
    project_name: str = "CSNet-IDA"
    subtitle: str = "Two-Stage Network Intrusion Detection & Security Intelligence Platform"
    architecture: str = "Two-Stage Hierarchical Random Forest"
    stage1_classifier: str = "Random Forest (Binary: Normal vs. Attack, 100 Estimators)"
    stage1_threshold: float = 0.40
    stage2_classifier: str = "Random Forest (Multiclass: DoS, Probe, R2L, U2R, 100 Estimators, Balanced Class Weights)"
    preprocessor: str = "Scikit-Learn ColumnTransformer (OneHotEncoder for 3 Categorical, Passthrough for 37 Numerical)"
    input_feature_count: int = 40
    transformed_feature_count: int = 120
    attack_families: List[str] = ["DoS", "Probe", "R2L", "U2R"]


class IncidentNote(BaseModel):
    id: str = Field(description="Unique note identifier")
    text: str = Field(description="Analyst note content")
    timestamp: str = Field(description="Timestamp when note was recorded")
    analyst: str = Field(default="SOC Analyst", description="Author or identity of the analyst")


class AddNoteRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Content of analyst note")
    analyst: Optional[str] = Field(default="SOC Analyst", description="Author or identity of the analyst")


class IncidentTimelineEvent(BaseModel):
    status: str = Field(description="Lifecycle status: New, Investigating, Confirmed, Resolved")
    timestamp: str = Field(description="Timestamp of lifecycle transition")
    note: Optional[str] = Field(default=None, description="Context or reason for status transition")
    actor: Optional[str] = Field(default="System", description="Entity initiating transition")


class IncidentUpdateRequest(BaseModel):
    status: str = Field(description="New status: New, Investigating, Confirmed, Resolved")
    notes: Optional[str] = Field(default=None, description="Optional transition note or rationale")
    analyst: Optional[str] = Field(default="SOC Analyst", description="Analyst performing update")


class SimulationStepRequest(BaseModel):
    scenario: str = Field(default="mixed_enterprise", description="Scenario identifier")
    step_index: Optional[int] = None
    seed: Optional[int] = None

