"""The student simulator must learn baselines exactly as production does,
otherwise its results would not describe the real system."""
import importlib.util
import random
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services import behavior_service
from app.services.context_capture import DEMO_LOCATIONS

GENERATOR = Path(__file__).resolve().parents[2] / "ml" / "training" / "generate_student_dataset.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_student_dataset", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def production_profile():
    return SimpleNamespace(known_locations="[]", known_devices="[]", known_browsers="[]",
                           known_ips="[]", known_os="[]", usual_login_hour_start=8,
                           usual_login_hour_end=22, average_failed_attempts=0,
                           total_logins=0, successful_logins=0, last_login_at=None)


def test_simulator_profile_matches_behavior_service():
    generator = load_generator()
    simulated, real = generator.Profile(), production_profile()
    rng = random.Random(1)
    for _ in range(200):
        event = dict(location=rng.choice(list(DEMO_LOCATIONS)), device=rng.choice(["Phone", "Laptop"]),
                     browser=rng.choice(["Chrome", "Edge"]), ip=f"100.64.0.{rng.randint(1, 9)}",
                     os_name=rng.choice(["Windows", "Android"]), hour=rng.randint(0, 23))
        simulated.learn(event["location"], event["device"], event["browser"], event["ip"],
                        event["os_name"], event["hour"])
        behavior_service.update_profile_after_login(
            MagicMock(), real, location=event["location"], device=event["device"],
            browser=event["browser"], ip_address=event["ip"], operating_system=event["os_name"],
            login_hour=event["hour"], failed_attempt_count=0, authentication_result="success")
        snapshot = behavior_service.profile_snapshot(real)
        assert sorted(simulated.locations) == snapshot["known_locations"]
        assert sorted(simulated.devices) == snapshot["known_devices"]
        assert sorted(simulated.browsers) == snapshot["known_browsers"]
        assert sorted(simulated.ips) == snapshot["known_ips"]
        assert sorted(simulated.os_names) == snapshot["known_os"]
        assert (simulated.start, simulated.end) == (snapshot["usual_hour_start"], snapshot["usual_hour_end"])
        assert (simulated.total, simulated.successful) == (snapshot["total_logins"], snapshot["successful_logins"])
        # Sets iterate in a different order, so summation may differ in the last float digit.
        assert simulated._coords == pytest.approx(behavior_service.average_known_coordinates(real))
