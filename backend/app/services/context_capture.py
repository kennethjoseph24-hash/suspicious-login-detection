"""
Captures login context from the incoming HTTP request. Real geolocation-by-IP
requires a paid/external service and internet access, which is not reliable
in a local classroom demo, so this project uses a clearly-labelled DEMO
location picker instead (see DemoContext in schemas/auth.py). The IP address,
browser and OS ARE captured for real from the actual HTTP request/User-Agent.
"""
from user_agents import parse as parse_user_agent

DEMO_LOCATIONS = {
    "Hyderabad": (17.3850, 78.4867),
    "Bangalore": (12.9716, 77.5946),
    "Mumbai": (19.0760, 72.8777),
    "Delhi": (28.7041, 77.1025),
    "New York": (40.7128, -74.0060),
}


def get_client_ip(request) -> str:
    # Forwarded headers are handled only by a configured trusted ASGI proxy.
    return request.client.host if request.client else "127.0.0.1"


def parse_device_context(user_agent_string: str):
    ua = parse_user_agent(user_agent_string or "")
    device = ua.device.family if ua.device and ua.device.family != "Other" else "Desktop/Laptop"
    # Families only: including versions made every browser auto-update look like a new browser.
    browser = (ua.browser.family or "").strip() or "Unknown Browser"
    os_name = (ua.os.family or "").strip() or "Unknown OS"
    return device, browser, os_name


def resolve_demo_location(location_name: str):
    """Returns (lat, lon) for a known demo location, or (None, None)."""
    coords = DEMO_LOCATIONS.get(location_name)
    if coords:
        return coords
    return None, None
