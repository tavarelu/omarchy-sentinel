// SPDX-License-Identifier: Apache-2.0
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "SentinelModel.js" as Model

// The Sentinel popup, version 2.
//
// Top to bottom: the daemon's state, a three-chip severity filter that the
// daemon shares through notify-prefs.json, then one card per open alert with
// a severity stripe, a folder button, an optional risk meter, and the same
// action set the CLI offers. Approve and Dismiss run the CLI directly; Kill
// and Investigate open a floating terminal because one needs a confirm and the
// other a pager. BarWidget.qml owns the file watchers and the CLI; this panel
// only draws and asks.
Panel {
  id: root
  moduleName: "tav.sentinel"
  ipcTarget: "tav.sentinel"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color track: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.12)
  // Used to notch the risk meter's band boundaries out of the track.
  readonly property color surface: Color.background
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: hostWidget && hostWidget.openRows ? hostWidget.openRows : []
  readonly property var prefs: hostWidget && hostWidget.prefs ? hostWidget.prefs : Model.defaultPrefs()
  readonly property int hiddenCount: hostWidget ? hostWidget.hiddenCount : 0
  readonly property var burst: hostWidget ? hostWidget.burst : null
  readonly property bool paused: hostWidget ? hostWidget.paused === true : false
  readonly property string stateDir: hostWidget ? hostWidget.stateDir : ""
  readonly property string pluginDir: String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "").replace(/\/$/, "")

  property string daemonState: "unknown"
  property bool unitInstalled: false
  property double nowMs: Date.now()
  property int cursor: 0
  property bool cursorActive: false

  readonly property string daemonLine: !unitInstalled
    ? "Daemon not installed"
    : (daemonState === "active" ? "Daemon running" : "Daemon " + daemonState)
  readonly property string countLine: {
    var base = paused
      ? "Notifications paused"
      : (rows.length === 0 ? "No open alerts" : rows.length + " open alert" + (rows.length === 1 ? "" : "s"))
    if (burst && burst.active) base += " · burst: " + burst.total + " collapsed"
    return base
  }

  function refresh() {
    nowMs = Date.now()
    statusProcess.running = true
    unitProcess.running = true
    if (hostWidget && typeof hostWidget.reloadFiles === "function") hostWidget.reloadFiles()
  }

  function open() {
    refresh()
    root.controller.show()
  }

  function close() {
    cursorActive = false
    root.controller.hide()
  }

  function toggle() {
    if (root.opened) root.close()
    else root.open()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  function selected() {
    if (rows.length === 0) return null
    return rows[Math.max(0, Math.min(cursor, rows.length - 1))]
  }

  function act(alert, verb, extra) {
    if (!alert || !hostWidget) return
    var args = [String(alert.id), verb]
    if (extra) for (var i = 0; i < extra.length; i++) args.push(extra[i])
    hostWidget.run(args)
    refreshLater.restart()
  }

  function actInTerminal(alert, verb) {
    if (!alert || !hostWidget) return
    hostWidget.runInTerminal([String(alert.id), verb])
    root.close()
  }

  function approveHere(alert) { act(alert, "approve", ["--scope", "this-repo"]) }
  function approveAnywhere(alert) { act(alert, "approve", ["--scope", "forever"]) }
  function dismiss(alert) { act(alert, "dismiss") }
  function kill(alert) { actInTerminal(alert, "kill") }
  function investigate(alert) { actInTerminal(alert, "investigate") }
  function openLocation(alert) { if (hostWidget) hostWidget.openLocation(alert) }
  function openLogs() { if (hostWidget) hostWidget.openLogs() }
  function pauseOneHour() { if (hostWidget) hostWidget.pauseOneHour(); refreshLater.restart() }
  function toggleSeverity(sev) {
    if (!hostWidget) return
    hostWidget.setSeverity(sev, prefs[sev] === false)
    refreshLater.restart()
  }
  function showAll() { if (hostWidget) hostWidget.showAll(); refreshLater.restart() }

  function installDaemon() {
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", pluginDir + "/scripts/install-daemon.sh", "--apply"])
    root.close()
  }

  function startDaemon() {
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", "systemctl", "--user", "start", "sentinel.service"])
    refreshLater.restart()
  }

  function moveCursor(dy) {
    if (rows.length === 0) return
    cursorActive = true
    cursor = Math.max(0, Math.min(rows.length - 1, cursor + dy))
  }

  Timer {
    id: refreshLater
    interval: 400
    repeat: false
    onTriggered: root.refresh()
  }

  Timer {
    interval: 1000
    running: root.opened
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  Process {
    id: statusProcess
    running: false
    command: ["systemctl", "--user", "is-active", "sentinel.service"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var s = String(text || "").trim()
        root.daemonState = s === "" ? "unknown" : s
      }
    }
  }

  Process {
    id: unitProcess
    running: false
    command: ["systemctl", "--user", "list-unit-files", "--no-legend", "sentinel.service"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.unitInstalled = String(text || "").indexOf("sentinel.service") !== -1
    }
  }

  // Banded track-and-fill meter for a SkillSpector score (D-008, 2026-09-06:
  // the Owner picked the bar over a ring gauge). Bands follow SkillSpector's own
  // scale -- 0 to 20 SAFE, 21 to 50 CAUTION, 51 and up DO NOT INSTALL -- and the
  // band text comes from the scan's own verdict whenever it carries one, so the
  // panel never invents a verdict of its own.
  component RiskMeter: Item {
    id: meter
    property real value: -1
    property string verdict: ""
    readonly property real cautionAt: 0.20
    readonly property real dangerAt: 0.50
    readonly property bool alarming: value >= dangerAt
    readonly property bool caution: value >= cautionAt && value < dangerAt
    readonly property color fillColor: alarming ? root.urgent
      : caution ? Qt.rgba(root.urgent.r, root.urgent.g, root.urgent.b, 0.55)
      : root.foreground
    readonly property string bandText: verdict !== "" ? verdict
      : alarming ? "DO NOT INSTALL" : caution ? "CAUTION" : "SAFE"
    visible: value >= 0
    implicitHeight: visible ? Style.space(14) : 0

    Rectangle {
      id: meterTrack
      anchors.left: parent.left
      anchors.right: verdictLabel.left
      anchors.rightMargin: Style.spacing.md
      anchors.verticalCenter: parent.verticalCenter
      height: Math.max(Style.space(4), Math.round(Style.spacing.controlHeight * 0.14))
      radius: height / 2
      color: root.track
    }

    Rectangle {
      anchors.left: meterTrack.left
      anchors.verticalCenter: meterTrack.verticalCenter
      height: meterTrack.height
      radius: meterTrack.radius
      width: meterTrack.width * Math.max(0, Math.min(1, meter.value))
      color: meter.fillColor
      Behavior on width { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
    }

    // Band boundaries, drawn as gaps in the track so the score can be read
    // against SAFE / CAUTION / DO NOT INSTALL without a legend.
    Repeater {
      model: [meter.cautionAt, meter.dangerAt]
      Rectangle {
        x: meterTrack.x + Math.round(meterTrack.width * modelData) - width / 2
        anchors.verticalCenter: meterTrack.verticalCenter
        width: Math.max(1, Math.round(meterTrack.height * 0.34))
        height: meterTrack.height
        color: root.surface
        opacity: 0.9
      }
    }

    Text {
      id: verdictLabel
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      text: Math.round(meter.value * 100) + " · " + meter.bandText
      color: meter.alarming ? root.urgent : root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Component {
    id: logsButton
    PanelActionButton {
      iconText: "󰈙"
      tooltipText: "Open the log folder"
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: root.openLogs()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(540))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveCursor(dy) }
      onActivateRequested: root.investigate(root.selected())
      onDeleteRequested: root.dismiss(root.selected())
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "j") root.moveCursor(1)
        else if (t === "k") root.moveCursor(-1)
        else if (t === "a") root.approveHere(root.selected())
        else if (t === "A") root.approveAnywhere(root.selected())
        else if (t === "x") root.kill(root.selected())
        else if (t === "i") root.investigate(root.selected())
        else if (t === "d") root.dismiss(root.selected())
        else if (t === "o") root.openLocation(root.selected())
        else if (t === "1") root.toggleSeverity("high")
        else if (t === "2") root.toggleSeverity("medium")
        else if (t === "3") root.toggleSeverity("low")
        else if (t === "p") root.pauseOneHour()
        else if (t === "r") root.refresh()
      }
    }

    Column {
      id: column
      width: parent.width
      spacing: Style.spacing.lg

      PanelHero {
        width: parent.width
        title: "Sentinel"
        meta: root.daemonLine
        detail: root.countLine
        foreground: root.foreground
        fontFamily: root.fontFamily
        trailingControl: logsButton
      }

      // Daemon controls: only the one that applies is shown.
      Row {
        width: parent.width
        spacing: Style.spacing.md
        visible: !root.unitInstalled || root.daemonState !== "active"

        Button {
          visible: !root.unitInstalled
          text: "Install daemon"
          iconText: "󰏗"
          bordered: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.installDaemon()
        }

        Button {
          visible: root.unitInstalled && root.daemonState !== "active"
          text: "Start daemon"
          iconText: "󰐊"
          bordered: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.startDaemon()
        }

        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: root.unitInstalled ? "Not watching until it runs." : "Runs as you, never root. Metadata only."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }
      }

      PanelSeparator {
        width: parent.width
        foreground: root.foreground
      }

      // ---- Severity filter. Shared with the daemon: off hides the alerts
      //      here and stops their toasts. Tamper alerts ignore it.
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        Text {
          text: "SHOW AND TOAST"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.letterSpacing: 1
        }

        Row {
          id: filterRow
          width: parent.width
          spacing: Style.spacing.md
          readonly property real cellWidth: (width - spacing * 2) / 3

          Repeater {
            model: ["high", "medium", "low"]

            Button {
              required property string modelData
              required property int index
              width: filterRow.cellWidth
              text: modelData.charAt(0).toUpperCase() + modelData.slice(1)
              iconText: root.prefs[modelData] === false ? "󰄱" : "󰄵"
              tooltipText: String(index + 1)
              bordered: true
              selected: root.prefs[modelData] !== false
              foreground: modelData === "high" ? root.urgent : root.foreground
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.toggleSeverity(modelData)
            }
          }
        }

        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "Off hides those alerts here and stops their toasts. Tamper alerts always show."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      PanelSeparator {
        width: parent.width
        foreground: root.foreground
      }

      // ---- Empty states.
      Text {
        visible: root.rows.length === 0 && root.hiddenCount === 0
        width: parent.width
        text: root.paused ? "Paused. Logging continues; toasts resume when the pause ends." : "Nothing changed the shape of a session. Normal coding stays silent."
        wrapMode: Text.WordWrap
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      Row {
        visible: root.rows.length === 0 && root.hiddenCount > 0
        width: parent.width
        spacing: Style.spacing.md

        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: root.hiddenCount + " alert" + (root.hiddenCount === 1 ? "" : "s") + " hidden by the filter."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Button {
          text: "Show all"
          foreground: root.foreground
          fontFamily: root.fontFamily
          fontSize: Style.font.bodySmall
          onClicked: root.showAll()
        }
      }

      // ---- Alert cards.
      Repeater {
        model: root.rows

        Rectangle {
          id: card
          required property var modelData
          required property int index
          readonly property bool isSelected: root.cursorActive && root.cursor === index
          readonly property string sev: String(modelData.severity || "")
          readonly property bool isHigh: sev === "high"
          readonly property bool sticky: Model.isSticky(modelData)
          readonly property bool hasPids: modelData.pids && modelData.pids.length > 0
          readonly property bool canOpen: Model.openArgv(modelData) !== null
          readonly property real riskValue: Model.riskValue(modelData)

          width: column.width
          implicitHeight: cardColumn.implicitHeight + Style.spacing.lg * 2
          radius: Style.cornerRadius
          color: isSelected ? root.selectedFill : (cardHover.hovered ? root.hoverFill : "transparent")

          HoverHandler { id: cardHover }

          // Severity stripe: urgent for high, fading for medium and low.
          Rectangle {
            x: 0
            y: Style.spacing.lg
            width: Style.space(3)
            height: parent.height - Style.spacing.lg * 2
            radius: width / 2
            color: card.isHigh || card.sticky ? root.urgent : root.foreground
            opacity: card.isHigh || card.sticky ? 1 : (card.sev === "medium" ? 0.55 : 0.25)
          }

          Column {
            id: cardColumn
            x: Style.spacing.lg + Style.space(6)
            y: Style.spacing.lg
            width: parent.width - Style.spacing.lg * 2 - Style.space(6)
            spacing: Style.spacing.sm

            Row {
              id: headRow
              width: parent.width
              spacing: Style.spacing.md

              OpticalGlyph {
                width: Style.space(18)
                height: Style.space(18)
                text: Model.ruleGlyph(card.modelData)
                fontFamily: root.fontFamily
                fontSize: Style.font.icon
                color: card.isHigh || card.sticky ? root.urgent : root.foreground
              }

              Text {
                width: parent.width - Style.space(18) - timeLabel.implicitWidth - openButton.width - Style.spacing.md * 3
                text: String(card.modelData.summary || card.modelData.rule || "")
                elide: Text.ElideRight
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.weight: card.isHigh ? Font.DemiBold : Font.Normal
              }

              Text {
                id: timeLabel
                anchors.verticalCenter: parent.verticalCenter
                text: Model.relativeTime(card.modelData.ts, root.nowMs)
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              PanelActionButton {
                id: openButton
                anchors.verticalCenter: parent.verticalCenter
                visible: card.canOpen
                iconText: "󰉋"
                tooltipText: "o: open folder"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.openLocation(card.modelData)
              }
            }

            Text {
              width: parent.width
              text: Model.severityLabel(card.modelData) + "  ·  " + String(card.modelData.rule || "") + (Model.whereLabel(card.modelData) !== "" ? "  ·  " + Model.whereLabel(card.modelData) : "") + (card.sticky ? "  ·  tamper" : "")
              elide: Text.ElideRight
              color: card.isHigh || card.sticky ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.letterSpacing: 0.5
            }

            RiskMeter {
              width: parent.width
              value: card.riskValue
              verdict: Model.riskVerdict(card.modelData)
            }

            // Equal-width action cells so the row never leaves the card.
            Row {
              id: actionRow
              width: parent.width
              spacing: Style.spacing.sm
              readonly property int count: 4 + (card.hasPids ? 1 : 0)
              readonly property real cellWidth: (width - spacing * (count - 1)) / count

              Button {
                width: actionRow.cellWidth
                text: "Approve"
                tooltipText: Model.isWriteRule(card.modelData) ? "a: allow writes to this file" : "a: allow this pattern in this repository"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.spacing.sm
                onClicked: root.approveHere(card.modelData)
              }
              Button {
                width: actionRow.cellWidth
                text: "Anywhere"
                tooltipText: Model.isWriteRule(card.modelData) ? "A: allow this file, never expires" : "A: allow this pattern everywhere, never expires"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.spacing.sm
                onClicked: root.approveAnywhere(card.modelData)
              }
              Button {
                visible: card.hasPids
                width: actionRow.cellWidth
                text: "Kill"
                tooltipText: "x: confirm in a terminal"
                foreground: root.urgent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.spacing.sm
                onClicked: root.kill(card.modelData)
              }
              Button {
                width: actionRow.cellWidth
                text: "Investigate"
                tooltipText: "i or Enter: evidence with citations"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.spacing.sm
                onClicked: root.investigate(card.modelData)
              }
              Button {
                width: actionRow.cellWidth
                text: "Dismiss"
                tooltipText: "d: close without allowlisting"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.spacing.sm
                onClicked: root.dismiss(card.modelData)
              }
            }
          }
        }
      }

      PanelSeparator {
        width: parent.width
        foreground: root.foreground
      }

      // ---- Footer: controls on one row, the key legend wrapped beneath so
      //      it can never run past the popup edge.
      Column {
        width: parent.width
        spacing: Style.spacing.sm

        Row {
          spacing: Style.spacing.md

          Button {
            text: root.paused ? "Paused" : "Pause 1h"
            iconText: "󰏤"
            enabled: !root.paused
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: root.pauseOneHour()
          }
          Button {
            text: "Refresh"
            iconText: "󰑐"
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: root.refresh()
          }
          Button {
            text: "Logs"
            iconText: "󰈙"
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: root.openLogs()
          }
        }

        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "j k move · a approve · A anywhere · x kill · i investigate · d dismiss · o open · 1 2 3 filter · p pause · r refresh"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
