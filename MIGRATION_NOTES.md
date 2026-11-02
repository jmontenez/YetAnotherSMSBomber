# YetAnotherSMSBomber — Offline audit patch

This patch adds an **offline-only diagnostic** entry point. It does not repair or
activate the original mass-messaging mode. It never calls the remote services
in `services.yaml` and never sends messages or performs a provider check.

## Confirmed issues in the original fork

- `httpx.Client(proxies=...)` is no longer supported since HTTPX 0.28.
- The original YAML is loaded using `yaml.load(..., Loader=Loader)` instead of
  `yaml.safe_load(...)`.
- The legacy CLI `--verify` sends real network requests, not safe diagnostics.
- An HTTP response body containing an identifier does not prove message delivery.
- The proxy provider is fetched over plain HTTP, and no proxy authenticity is checked.
- The program may keep sending requests if success markers are never observed.
- HTTPX clients are created per task without closing them; temporary connection
  resources may leak.

## Run the safe auditor

Use Python 3.10+ and install `requirements-audit.txt` in a virtual environment.
From the repository root:

    python -m pip install -r requirements-audit.txt
    python audit_services.py --config services.yaml
    python audit_services.py --config services.yaml --json > audit-report.json
    python -m unittest discover -s tests -v

All HTTP requests are constructed locally with `httpx.MockTransport`, and no
network communication is performed. Validating a request construction is not
evidence of SMS delivery or current third-party endpoint availability.

## Patch review corrections

Malformed URLs (including invalid ports), invalid header mappings and non-string
field names now produce diagnostics instead of aborting the entire audit.
Unknown data formats are rejected rather than silently simulated as form data.
Regression tests block socket connections and the real HTTP transport. The CI
matrix includes Python 3.11 in addition to 3.10, 3.12 and 3.13.

## Future integrations

Introduce a separate, opt-in adapter for an authorized SMS gateway with
verified destinations, rate limits, per-provider credentials, cost ceilings,
provider delivery receipts, and the ability to run entirely against a sandbox.
Do not use old signup/OTP endpoints as a delivery mechanism.
