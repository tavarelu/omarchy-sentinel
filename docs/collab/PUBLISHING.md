# Publishing to the Omarchy plugin marketplace

Sources: https://plugins.omarchy.org/develop.html, https://plugins.omarchy.org/publish.html, and the shell's own contract at `/usr/share/omarchy/shell/plugins/README.md` and `/usr/bin/omarchy-plugin-validate` on Omarchy 4.0.2 (read 2026-09-04).

## What a plugin is
- A directory with `manifest.json` and one QML entry point per declared kind. Kinds and entry keys: `bar-widget` -> `entryPoints.barWidget`, `panel` -> `panel`, `overlay` -> `overlay`, `menu` -> `menu`, `service` -> `service`, `bar` -> `bar`.
- Installed plugins live at `~/.config/omarchy/plugins/<id>/` as git checkouts. First-party ones live under `/usr/share/omarchy/shell/plugins/`.
- Plugins run inside the `omarchy-shell` Quickshell process, unsandboxed, as the user. Do not spawn a second Quickshell. Use `Process`, `FileView` with `watchChanges`, and `bar.run(...)` for commands.

## Manifest (required fields)
```json
{
  "schemaVersion": 1,
  "id": "yourname.sentinel",
  "name": "Sentinel",
  "version": "0.1.0",
  "author": "Your name",
  "license": "Apache-2.0",
  "description": "Short marketplace summary.",
  "kinds": ["bar-widget"],
  "entryPoints": { "barWidget": "BarWidget.qml" },
  "barWidget": {
    "displayName": "Sentinel",
    "description": "Longer description shown in the bar widget catalogue.",
    "category": "AI",
    "allowMultiple": false,
    "defaultSection": "right"
  }
}
```
Rules the validator enforces: `schemaVersion` is the number 1; `id` matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`, contains no `..`, and is not `omarchy.*`; `kinds` is a non-empty array; every entry point is a relative path with no `..` that exists; `barWidget.defaultSection` is left, center or right; no symlinks anywhere except inside `.git`.

## Bar widget contract (from `omarchy.clock`)
- Root is `BarWidget { moduleName: "<id>" }` from `qs.Ui`; it must expose `open()`, `close()`, `opened`, and forward `closeForPopoutSwitch` and `popoutSwitchClosing` when it hosts a panel.
- The panel is a `Panel { moduleName: "<id>"; ipcTarget: "<id>"; manageIpc: false }` loaded through a `Loader`; inject `bar`, `settings`, `anchorItem`, `hostWidget` into it after load.
- An `IpcHandler { target: "<id>" }` with `open`, `close`, `show`, `hide`, `toggle` lets `omarchy-shell shell summon <id> '{}'` and `hide` drive it.
- Use `WidgetButton` for the bar slot; read theme values from `bar.foreground`, `Color.*`, `Style.*`.

## Develop loop
```sh
omarchy plugin validate .
qmllint -I /usr/share/omarchy/shell BarWidget.qml Panel.qml
omarchy plugin add /path/or/git-url --enable        # installs into ~/.config/omarchy/plugins/<id>
omarchy-shell shell summon <id> '{}'                 # open the panel
omarchy-shell shell hide <id>
omarchy plugin disable <id>; omarchy plugin enable <id> --section right
omarchy plugin remove <id>
```
Test the whole lifecycle: open, close, disable, re-enable, shell restart, removal. Remove `omarchy.clonedFrom` from the manifest before publishing if you started from a clone.

## Publish
1. Public GitHub repository, `manifest.json` at the root, README with Install, Usage, Configure, Remove sections, a LICENSE file, optional preview image.
2. Run `omarchy plugin validate` on the exact commit you will submit.
3. Open the submission form: https://github.com/omacom/omarchy-plugin-marketplace/issues/new?template=submit-plugin.yml with the repository link, a category, and tags. Automated checks validate the current commit, then a maintainer approves.
4. Releases are pushes to the repo; users update with `omarchy plugin update <id>`. Bump `version` in the manifest on every release.

## What the marketplace does not do
It does not sandbox or audit plugins. "The marketplace validates listings, not plugin security." For a security tool that is a reputational point: our repo must carry a threat model, SECURITY.md, and CI that runs SkillSpector on itself.
