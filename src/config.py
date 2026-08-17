"""
Configuration and constants for the CSNet-IDA Intrusion Detection System.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
APP_DIR = BASE_DIR / "app"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# Model Artifact Paths
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor_final.pkl"
STAGE1_MODEL_PATH = MODELS_DIR / "random_forest_final.pkl"
STAGE1_THRESHOLD_PATH = MODELS_DIR / "threshold_final.pkl"
STAGE2_MODEL_PATH = MODELS_DIR / "attack_family_random_forest_final.pkl"
STAGE2_LABELS_PATH = MODELS_DIR / "attack_family_labels_final.pkl"
TWO_STAGE_BUNDLE_PATH = MODELS_DIR / "intrusion_detection_two_stage_final.pkl"

# Default Stage 1 Threshold
DEFAULT_STAGE1_THRESHOLD = 0.40

# Complete 40-feature schema in exact order expected by the preprocessor
FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERICAL_FEATURES = [f for f in FEATURE_NAMES if f not in CATEGORICAL_FEATURES]

# Categorical Option Domains
PROTOCOL_TYPES = ["tcp", "udp", "icmp"]

SERVICES = [
    "IRC", "X11", "Z39_50", "aol", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
    "discard", "domain", "domain_u", "echo", "eco_i", "ecr_i", "efs", "exec", "finger", "ftp",
    "ftp_data", "gopher", "harvest", "hostnames", "http", "http_2784", "http_443", "http_8001",
    "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login", "mtp", "name", "netbios_dgm",
    "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp", "ntp_u", "other", "pm_dump", "pop_2",
    "pop_3", "printer", "private", "red_i", "remote_job", "rje", "shell", "smtp", "sql_net",
    "ssh", "sunrpc", "supdup", "systat", "telnet", "tftp_u", "tim_i", "time", "urh_i", "urp_i",
    "uucp", "uucp_path", "vmnet", "whois"
]

FLAGS = [
    "SF", "S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3", "SH", "OTH", "RSTOS0"
]

ATTACK_FAMILIES = ["DoS", "Probe", "R2L", "U2R"]

ATTACK_FAMILY_DESCRIPTIONS = {
    "Normal": "Legitimate network traffic with normal packet parameters.",
    "DoS": "Denial of Service — Attempts to overwhelm system resources (e.g., Neptune, Smurf, Pod).",
    "Probe": "Surveillance / Reconnaissance — Probing network topology and open ports (e.g., IPSweep, Nmap, Satan).",
    "R2L": "Remote-to-Local — Unauthorized remote access attempt (e.g., Guess Password, Warezclient, FTP Write).",
    "U2R": "User-to-Root — Local privilege escalation to superuser (e.g., Buffer Overflow, Rootkit, Loadmodule)."
}
