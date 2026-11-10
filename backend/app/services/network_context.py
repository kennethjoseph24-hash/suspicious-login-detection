"""Institution context is determined before both ML and rule evaluation."""
import hmac
import json
from ipaddress import ip_address, ip_network
from app.config import settings

CAMPUS = "Campus Network"
LAB = "Laboratory Device"
EXTERNAL = "External Connection"


def classify_context(address, lab_token=None, demo_lab_id=None):
    try:
        address = ip_address(address)
        campus = any(address in ip_network(c.strip(), strict=False)
                     for c in settings.campus_ip_ranges.split(",") if c.strip())
    except ValueError:
        return EXTERNAL
    if not campus:
        return EXTERNAL
    registry = json.loads(settings.lab_device_tokens)
    registered = lab_token and any(hmac.compare_digest(lab_token, token)
                                  for token in registry.values())
    demo_registered = settings.demo_context_enabled and demo_lab_id == "lab-pc-01"
    return LAB if registered or demo_registered else CAMPUS


def contextualize_features(features, context):
    adjusted = dict(features)
    if context in (CAMPUS, LAB):
        adjusted["ip_novelty"] = 0
    if context == LAB:
        for key in ("device_novelty", "browser_novelty", "os_novelty"):
            adjusted[key] = 0
    return adjusted
