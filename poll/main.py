import os
import json
import time
from datetime import datetime

import growattServer


def main():
    api_token = os.environ.get("GROWATT_API_TOKEN")
    if not api_token:
        raise ValueError("GROWATT_API_TOKEN environment variable is required")

    device_sn = os.environ.get("GROWATT_DEVICE_SN")
    if not device_sn:
        raise ValueError("GROWATT_DEVICE_SN environment variable is required")

    poll_interval = int(os.environ.get("POLL_INTERVAL_SECONDS", "110"))

    api = growattServer.OpenApiV1(token=api_token)

    while True:
        try:
            detail_response = api.sph_detail(device_sn=device_sn)
            energy_response = api.sph_energy(device_sn=device_sn)

            response = {"detail": detail_response, "energy": energy_response}

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}.json"

            with open(filename, "w") as f:
                json.dump(response, f, indent=2)

            print(f" * {filename}")

        except Exception as e:
            print(f"poll error: {e}")

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
