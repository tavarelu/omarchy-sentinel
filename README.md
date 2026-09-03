# Omarchy Sentinel

User-space AI-agent security control plane for Omarchy Linux.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

XDG paths (override with `XDG_CONFIG_HOME` / `XDG_STATE_HOME`):

- Config: `~/.config/sentinel/` (default `config.toml`)
- State: `~/.local/state/sentinel/`

Do not commit secrets from `~/.config/sentinel`.
