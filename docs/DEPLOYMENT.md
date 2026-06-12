# CI/CD Integration

The pattern is always the same: provide the master key via the `DOTSEAL_MASTER_KEY` environment variable (from your platform's secret store), commit only `.env.enc`, and either decrypt to a file or load at runtime.

## GitHub Actions

Store the key as a repository/environment **secret** named `DOTSEAL_MASTER_KEY`.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DOTSEAL_MASTER_KEY: ${{ secrets.DOTSEAL_MASTER_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install dotseal

      # Option A: decrypt to a real .env for tools that expect a file
      - run: dotseal decrypt .env.enc .env

      # Option B: load at runtime inside your app (no cleartext file)
      - run: python -c "from dotseal import load_env; load_env(); import app"
```

## Docker

Bake only the encrypted file into the image and pass the key at runtime:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install dotseal
COPY .env.enc .
COPY . .
# App calls load_env() on startup.
CMD ["python", "main.py"]
```

```bash
docker run -e DOTSEAL_MASTER_KEY="$(cat .dotseal.key)" my-image
```

```python
# main.py
from dotseal import load_env
load_env()   # picks up DOTSEAL_MASTER_KEY from the container env
```

## Kubernetes

Store the master key in a `Secret` and expose it as `DOTSEAL_MASTER_KEY`:

```yaml
env:
  - name: DOTSEAL_MASTER_KEY
    valueFrom:
      secretKeyRef:
        name: dotseal
        key: master-key
```

For asymmetric files, use `DOTSEAL_PRIVATE_KEY` (or mount `.dotseal.prv`) instead of the symmetric master key.

See also [Usage and CLI](USAGE.md), [Key Management](KEY_MANAGEMENT.md), and [Asymmetric Mode](ASYMMETRIC.md).
