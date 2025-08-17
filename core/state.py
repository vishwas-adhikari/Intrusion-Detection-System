# core/state.py
from collections import defaultdict

"""
This module defines the centralized detection state used across detectors.
By keeping all trackers here, we avoid using scattered global variables and
make state management more organized and maintainable.
"""

# Centralized dictionary for tracking detection-related states.
detection_state = {
    # Tracks ICMP packets (used for detecting pings and ICMP floods).
    # Key: source IP -> List of timestamps or packet metadata
    "icmp_packet_tracker": defaultdict(list),

    # Tracks TCP port scan activity.
    # Key: source IP -> dict of {destination IP -> set of destination ports probed}
    "port_scan_tracker": defaultdict(lambda: defaultdict(set)),

    # Additional trackers can be added here as we build more detectors.
}
