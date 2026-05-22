Attack Simulation Guide

Prerequisites:
- You must have explicit authorization to run tests against the target (local `bloome` instance).
- `docker` and `docker-compose` installed for isolated environments.
- `ffmpeg` on PATH for post-processing videos (optional but recommended).

Quickstart (local, isolated):

1. Start the stack (builds app, ZAP, attacker):

```bash
docker compose -f docker-compose.attack.yml up --build
```

2. The `attacker` service will run `scripts/attack_simulator.py` against `http://app:8000` and store results in `attack_results/`.

3. To run locally without Docker (requires Playwright installed and browsers):

```bash
python -m pip install -r requirements.txt
python scripts/attack_simulator.py --target http://localhost:8000 --output ./attack_results --use-zap
python scripts/recording_helper.py  # use annotate_video(...) to post-process
```

4. View results in the Streamlit dashboard (if available):

- Open the dashboard and navigate to the Attack Simulation section (dashboard/components/attack_simulation.py). The section will display `attack_results/last_run.json` and the recorded video if present.

Security & Compliance:
- Always run simulations in an isolated environment.
- Remove or redact any sensitive data captured during runs.
- Use `--use-zap` only if you understand ZAP scans may generate more intrusive checks; keep to baseline scans for authorized testing.

