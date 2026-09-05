# VAJRA Sandbox

A deliberately-vulnerable Flask application used by VAJRA's sandboxed exploit verifier to provide **binary, ground-truthed verification** of LLM-generated SQL injection payloads.

> [!CAUTION]
> **This application is intentionally insecure.** It must ONLY be run inside the Docker compose environment below. Never expose it to a network. Never run it on your host OS directly.

## Quick Start

```bash
# From the project root:
cd sandbox
docker compose up -d          # start in background
docker compose logs -f        # watch logs
docker compose down           # stop and remove
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/login` | **Vulnerable** login (SQLi target) |
| `POST` | `/verify` | High-level: submit a payload, get bypass verdict |
| `POST` | `/reset` | Restore DB to clean state |
| `GET`  | `/status` | Healthcheck + bypass audit log |

## How VAJRA Uses This

1. For payloads with `technique: sqli`, VAJRA fires extracted SQLi candidates at `/verify`
2. If any candidate achieves authentication bypass, verdict is upgraded to `VERIFIED_EXPLOIT`
3. Database is reset between each payload test via `/reset`
4. The Docker container has no external internet access (internal-only bridge network)

## Manual Testing

```bash
# Confirm it's up
curl http://127.0.0.1:5555/status

# Test a normal login (should fail)
curl -X POST http://127.0.0.1:5555/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "wrongpassword"}'

# Test a SQLi bypass (should succeed)
curl -X POST http://127.0.0.1:5555/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\": \"admin' --\", \"password\": \"anything\"}"

# Use the verify endpoint directly
curl -X POST http://127.0.0.1:5555/verify \
  -H 'Content-Type: application/json' \
  -d "{\"payload\": \"admin' --\"}"
```
