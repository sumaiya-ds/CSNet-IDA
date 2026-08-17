"""
Curated NSL-KDD benchmark presets and simulation stream samples for interactive IDS demonstration.
"""

import random
from typing import Dict, Any, List
from src.schemas import PresetResponse

PRESETS: Dict[str, Dict[str, Any]] = {
    "normal": {
        "id": "normal",
        "name": "Normal Connection",
        "family": "Normal",
        "label": "normal",
        "description": "Standard legitimate TCP FTP-data session with valid transmission metrics.",
        "data": {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "ftp_data",
            "flag": "SF",
            "src_bytes": 491.0,
            "dst_bytes": 0.0,
            "land": 0,
            "wrong_fragment": 0.0,
            "urgent": 0.0,
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": 0,
            "num_compromised": 0.0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 2.0,
            "srv_count": 2.0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 150.0,
            "dst_host_srv_count": 25.0,
            "dst_host_same_srv_rate": 0.17,
            "dst_host_diff_srv_rate": 0.03,
            "dst_host_same_src_port_rate": 0.17,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.05,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    "dos": {
        "id": "dos",
        "name": "DoS Attack (Neptune SYN Flood)",
        "family": "DoS",
        "label": "neptune",
        "description": "Denial of Service SYN flood against private network service with high SYN error rates (S0 flag).",
        "data": {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "S0",
            "src_bytes": 0.0,
            "dst_bytes": 0.0,
            "land": 0,
            "wrong_fragment": 0.0,
            "urgent": 0.0,
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": 0,
            "num_compromised": 0.0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 123.0,
            "srv_count": 6.0,
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 0.05,
            "diff_srv_rate": 0.07,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0,
            "dst_host_srv_count": 26.0,
            "dst_host_same_srv_rate": 0.1,
            "dst_host_diff_srv_rate": 0.05,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 1.0,
            "dst_host_srv_serror_rate": 1.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    "probe": {
        "id": "probe",
        "name": "Probe Attack (IPSweep)",
        "family": "Probe",
        "label": "ipsweep",
        "description": "Network reconnaissance sweep using ICMP Echo Request packets to map active host IP addresses.",
        "data": {
            "duration": 0.0,
            "protocol_type": "icmp",
            "service": "eco_i",
            "flag": "SF",
            "src_bytes": 18.0,
            "dst_bytes": 0.0,
            "land": 0,
            "wrong_fragment": 0.0,
            "urgent": 0.0,
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": 0,
            "num_compromised": 0.0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1.0,
            "srv_count": 1.0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1.0,
            "dst_host_srv_count": 16.0,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 1.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    "r2l": {
        "id": "r2l",
        "name": "R2L Attack (Warezclient)",
        "family": "R2L",
        "label": "warezclient",
        "description": "Remote-to-Local intrusion involving unauthorized FTP downloads and file access attempts.",
        "data": {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "ftp_data",
            "flag": "SF",
            "src_bytes": 334.0,
            "dst_bytes": 0.0,
            "land": 0,
            "wrong_fragment": 0.0,
            "urgent": 0.0,
            "hot": 0.0,
            "num_failed_logins": 0.0,
            "logged_in": 1,
            "num_compromised": 0.0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0.0,
            "num_file_creations": 0.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 2.0,
            "srv_count": 2.0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 2.0,
            "dst_host_srv_count": 20.0,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.2,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    "u2r": {
        "id": "u2r",
        "name": "U2R Attack (Rootkit)",
        "family": "U2R",
        "label": "rootkit",
        "description": "User-to-Root privilege escalation via Telnet session yielding root shell access and file manipulation.",
        "data": {
            "duration": 98.0,
            "protocol_type": "tcp",
            "service": "telnet",
            "flag": "SF",
            "src_bytes": 621.0,
            "dst_bytes": 8356.0,
            "land": 0,
            "wrong_fragment": 0.0,
            "urgent": 1.0,
            "hot": 1.0,
            "num_failed_logins": 0.0,
            "logged_in": 1,
            "num_compromised": 5.0,
            "root_shell": 1,
            "su_attempted": 0,
            "num_root": 14.0,
            "num_file_creations": 1.0,
            "num_shells": 0.0,
            "num_access_files": 0.0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1.0,
            "srv_count": 1.0,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0,
            "dst_host_srv_count": 4.0,
            "dst_host_same_srv_rate": 0.02,
            "dst_host_diff_srv_rate": 0.02,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    }
}

# Authentic pool of NSL-KDD test vectors for live stream simulation
STREAM_SAMPLES: List[Dict[str, Any]] = [
    # 1. Normal HTTP session
    {
        "flow_hint": "HTTP / Web Traffic",
        "ground_truth_label": "normal",
        "data": {
            "duration": 0.0, "protocol_type": "tcp", "service": "http", "flag": "SF",
            "src_bytes": 232.0, "dst_bytes": 8153.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 1, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 5.0,
            "srv_count": 5.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 30.0, "dst_host_srv_count": 255.0, "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.03, "dst_host_srv_diff_host_rate": 0.04,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 2. DoS Neptune (SYN Flood)
    {
        "flow_hint": "TCP / Private SYN Flood",
        "ground_truth_label": "neptune",
        "data": {
            "duration": 0.0, "protocol_type": "tcp", "service": "private", "flag": "S0",
            "src_bytes": 0.0, "dst_bytes": 0.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 123.0,
            "srv_count": 6.0, "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 0.05, "diff_srv_rate": 0.07, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 26.0, "dst_host_same_srv_rate": 0.1,
            "dst_host_diff_srv_rate": 0.05, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 3. Normal SMTP Mail Exchange
    {
        "flow_hint": "SMTP / Mail Transfer",
        "ground_truth_label": "normal",
        "data": {
            "duration": 0.0, "protocol_type": "tcp", "service": "smtp", "flag": "SF",
            "src_bytes": 864.0, "dst_bytes": 328.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 1, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 1.0,
            "srv_count": 1.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 224.0, "dst_host_same_srv_rate": 0.88,
            "dst_host_diff_srv_rate": 0.02, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 4. Probe IPSweep
    {
        "flow_hint": "ICMP / Echo Sweep",
        "ground_truth_label": "ipsweep",
        "data": {
            "duration": 0.0, "protocol_type": "icmp", "service": "eco_i", "flag": "SF",
            "src_bytes": 18.0, "dst_bytes": 0.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 1.0,
            "srv_count": 1.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 1.0, "dst_host_srv_count": 16.0, "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 1.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 5. Normal Domain / DNS Resolution
    {
        "flow_hint": "UDP / Domain Name Query",
        "ground_truth_label": "normal",
        "data": {
            "duration": 0.0, "protocol_type": "udp", "service": "domain_u", "flag": "SF",
            "src_bytes": 44.0, "dst_bytes": 134.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 3.0,
            "srv_count": 3.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 254.0, "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.01, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 6. R2L Warezclient
    {
        "flow_hint": "FTP-Data / Unauthorized Download",
        "ground_truth_label": "warezclient",
        "data": {
            "duration": 0.0, "protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
            "src_bytes": 334.0, "dst_bytes": 0.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 1, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 2.0,
            "srv_count": 2.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 2.0, "dst_host_srv_count": 20.0, "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.2,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 7. DoS Smurf (ICMP Amplification)
    {
        "flow_hint": "ICMP / Broadcast Amplification",
        "ground_truth_label": "smurf",
        "data": {
            "duration": 0.0, "protocol_type": "icmp", "service": "ecr_i", "flag": "SF",
            "src_bytes": 1032.0, "dst_bytes": 0.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 511.0,
            "srv_count": 511.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 255.0, "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 8. Probe Satan / PortScan
    {
        "flow_hint": "TCP / Port Reconnaissance",
        "ground_truth_label": "satan",
        "data": {
            "duration": 0.0, "protocol_type": "tcp", "service": "other", "flag": "REJ",
            "src_bytes": 0.0, "dst_bytes": 0.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 0.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 242.0,
            "srv_count": 7.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 1.0,
            "srv_rerror_rate": 1.0, "same_srv_rate": 0.03, "diff_srv_rate": 0.06, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 7.0, "dst_host_same_srv_rate": 0.03,
            "dst_host_diff_srv_rate": 0.07, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 1.0,
            "dst_host_srv_rerror_rate": 1.0
        }
    },
    # 9. U2R Rootkit
    {
        "flow_hint": "Telnet / Root Shell Exploit",
        "ground_truth_label": "rootkit",
        "data": {
            "duration": 98.0, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
            "src_bytes": 621.0, "dst_bytes": 8356.0, "land": 0, "wrong_fragment": 0.0, "urgent": 1.0,
            "hot": 1.0, "num_failed_logins": 0.0, "logged_in": 1, "num_compromised": 5.0, "root_shell": 1,
            "su_attempted": 0, "num_root": 14.0, "num_file_creations": 1.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 1.0,
            "srv_count": 1.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 4.0, "dst_host_same_srv_rate": 0.02,
            "dst_host_diff_srv_rate": 0.02, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    },
    # 10. R2L Guess Password
    {
        "flow_hint": "Telnet / Brute-force Login",
        "ground_truth_label": "guess_passwd",
        "data": {
            "duration": 60.0, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
            "src_bytes": 126.0, "dst_bytes": 179.0, "land": 0, "wrong_fragment": 0.0, "urgent": 0.0,
            "hot": 0.0, "num_failed_logins": 1.0, "logged_in": 0, "num_compromised": 0.0, "root_shell": 0,
            "su_attempted": 0, "num_root": 0.0, "num_file_creations": 0.0, "num_shells": 0.0,
            "num_access_files": 0.0, "is_host_login": 0, "is_guest_login": 0, "count": 1.0,
            "srv_count": 1.0, "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": 255.0, "dst_host_srv_count": 1.0, "dst_host_same_srv_rate": 0.0,
            "dst_host_diff_srv_rate": 0.02, "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }
    }
]


def get_all_presets() -> List[PresetResponse]:
    """Returns list of all preset objects for API consumption."""
    return [PresetResponse(**p) for p in PRESETS.values()]


def get_preset_by_id(preset_id: str) -> PresetResponse:
    """Returns single preset by id (case-insensitive)."""
    pid = preset_id.lower().strip()
    if pid not in PRESETS:
        raise KeyError(f"Preset '{preset_id}' not found. Available: {list(PRESETS.keys())}")
    return PresetResponse(**PRESETS[pid])


def get_random_simulation_sample() -> Dict[str, Any]:
    """Returns a random authentic connection vector from the stream simulation pool."""
    return random.choice(STREAM_SAMPLES)
