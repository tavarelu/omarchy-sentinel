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

## Omarchy menu

Sentinel menu rows live in `packaging/omarchy-menu-sentinel.jsonc` (ids: `sentinel`, `sentinel.alerts`, `sentinel.status`, `sentinel.inventory`, `sentinel.pause`).

```bash
# Preview merge into ~/.config/omarchy/extensions/omarchy-menu.jsonc (default)
scripts/install-menu.sh
# or explicitly:
scripts/install-menu.sh --dry-run

# Write after backup (*.sentinel-bak.<timestamp>)
scripts/install-menu.sh --apply
```

Then open the menu or run `omarchy menu summon sentinel` to confirm the rows.
