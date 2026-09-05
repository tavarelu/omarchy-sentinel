import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "SentinelModel.js" as Model

// Sentinel in the bar: a shield with the number of open alerts. Left click
// opens the panel; middle click pauses notifications for an hour; right click
// opens the alert list in a floating terminal for keyboard people.
//
// The widget never inspects agents itself. It watches the daemon's
// alerts.jsonl and pause_until under ~/.local/state/sentinel and draws what
// is there; every action runs the sentinel-action CLI.
BarWidget {
  id: root
  moduleName: "tav.sentinel"

  readonly property string home: Quickshell.env("HOME") || ""
  readonly property string stateDir: (Quickshell.env("XDG_STATE_HOME") || home + "/.local/state") + "/sentinel"
  readonly property string cliPath: String(setting("cliPath", "") || "")
  readonly property bool showLow: setting("showLowSeverity", false) === true

  property var allRows: []
  readonly property var openRows: Model.openAlerts(allRows, showLow)
  readonly property var counts: Model.countBySeverity(openRows)
  readonly property int openCount: openRows.length
  property double pauseUntilMs: 0
  readonly property bool paused: pauseUntilMs > Date.now()
  readonly property string glyph: "󰒃"

  function cliArgv(args) {
    var argv = [cliPath !== "" ? cliPath : "sentinel-action"]
    for (var i = 0; i < args.length; i++) argv.push(String(args[i]))
    return argv
  }

  function run(args) {
    Quickshell.execDetached(cliArgv(args))
  }

  function runInTerminal(args) {
    var argv = ["omarchy-launch-floating-terminal-with-presentation"]
    var cli = cliArgv(args)
    for (var i = 0; i < cli.length; i++) argv.push(cli[i])
    Quickshell.execDetached(argv)
  }

  function pauseOneHour() { run(["pause", "1h"]) }

  // Re-read the state files only. The panel calls this; it never calls
  // refresh(), which would recurse back into the panel.
  function reloadFiles() {
    alertsFile.reload()
    pauseFile.reload()
  }

  function refresh() {
    reloadFiles()
    if (panelLoader.item && panelLoader.item.refresh) panelLoader.item.refresh()
  }

  // ---- Panel lifecycle contract (Bar.findPanelWidget needs open/close/opened).
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  function open() { if (panelLoader.item) panelLoader.item.open() }
  function close() { if (panelLoader.item) panelLoader.item.close() }
  function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }

  readonly property real openPanelIndicatorWidth: button.labelWidth
  readonly property real openPanelIndicatorHeight: Math.max(Style.space(10), Math.round(Style.bar.iconSlot * 0.55))
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false
  function closeForPopoutSwitch() { if (panelLoader.item) panelLoader.item.closeForPopoutSwitch() }

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  // Never reload synchronously from fileChanged: on a file that does not
  // exist yet the signal re-fires inside reload() and the pair recurses until
  // the QML stack overflows (seen live as "Maximum call stack size exceeded"
  // every 30 s). Debounce through a timer, and do not chain reloads while the
  // file is missing; the 30 s timer picks it up once it appears.
  FileView {
    id: alertsFile
    path: root.stateDir + "/alerts.jsonl"
    watchChanges: true
    printErrors: false
    property bool missing: false
    onFileChanged: if (!missing) alertsReload.restart()
    onLoaded: { missing = false; root.allRows = Model.parseAlerts(text()) }
    onLoadFailed: { missing = true; root.allRows = [] }
  }

  Timer {
    id: alertsReload
    interval: 150
    repeat: false
    onTriggered: alertsFile.reload()
  }

  FileView {
    id: pauseFile
    path: root.stateDir + "/pause_until"
    watchChanges: true
    printErrors: false
    property bool missing: false
    onFileChanged: if (!missing) pauseReload.restart()
    onLoaded: { missing = false; root.pauseUntilMs = Model.parsePauseUntil(text()) }
    onLoadFailed: { missing = true; root.pauseUntilMs = 0 }
  }

  Timer {
    id: pauseReload
    interval: 150
    repeat: false
    onTriggered: pauseFile.reload()
  }

  // The state directory may not exist until the daemon first runs; a file
  // watch on a missing directory never fires, so rescan occasionally.
  Timer {
    interval: 30000
    running: true
    repeat: true
    onTriggered: root.reloadFiles()
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "tav.sentinel"

    function refresh(): void { root.broadcast("refresh") }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.togglePanel() }
    function pause(): void { root.pauseOneHour() }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.vertical ? root.glyph : (root.openCount > 0 ? root.glyph + " " + root.openCount : root.glyph)
    active: root.counts.high > 0 && !root.paused
    dimmed: root.paused || root.openCount === 0
    tooltipText: root.paused
      ? "Sentinel paused"
      : (root.openCount === 0 ? "Sentinel: no open alerts" : "Sentinel: " + root.openCount + " open alert" + (root.openCount === 1 ? "" : "s"))
    horizontalMargin: 8.75
    verticalPadding: 8.75

    onPressed: function(b) {
      if (b === Qt.MiddleButton) root.pauseOneHour()
      else if (b === Qt.RightButton) root.runInTerminal(["list"])
      else root.togglePanel()
    }
  }
}
