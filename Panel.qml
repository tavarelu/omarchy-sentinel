// SPDX-License-Identifier: Apache-2.0
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "SentinelModel.js" as Model

// The Sentinel popup: the daemon's health on top, then one card per open
// alert with the four responses the spec locks: Approve, Kill, Investigate,
// Dismiss. Approve and Dismiss run the CLI directly; Kill and Investigate
// open a floating terminal because one needs a confirm and the other a pager.
//
// BarWidget.qml owns the alert file watchers and the CLI; this panel only
// draws its rows and asks it to act.
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
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: hostWidget && hostWidget.openRows ? hostWidget.openRows : []
  readonly property bool paused: hostWidget ? hostWidget.paused === true : false
  readonly property string pluginDir: String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "").replace(/\/$/, "")

  // active | inactive | failed | unknown, from systemctl; unitInstalled says
  // whether the unit file exists at all, so the panel can offer Install.
  property string daemonState: "unknown"
  property bool unitInstalled: false
  property double nowMs: Date.now()
  property int cursor: 0
  property bool cursorActive: false

  readonly property string daemonLine: !unitInstalled
    ? "Daemon not installed"
    : (daemonState === "active" ? "Daemon running" : "Daemon " + daemonState)
  readonly property string countLine: paused
    ? "Notifications paused"
    : (rows.length === 0 ? "No open alerts" : rows.length + " open alert" + (rows.length === 1 ? "" : "s"))

  function refresh() {
    nowMs = Date.now()
    statusProcess.running = true
    unitProcess.running = true
    // reloadFiles, not refresh: the widget's refresh() calls back into this
    // function and the pair would recurse until the stack overflowed.
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
    // The daemon-side rewrite lands within milliseconds; give the watcher a beat.
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
  function pauseOneHour() { if (hostWidget) hostWidget.pauseOneHour(); refreshLater.restart() }

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

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    // Anchored to the widget, not centered on the bar: this lives in the right section.
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

      Text {
        visible: root.rows.length === 0
        width: parent.width
        text: root.paused ? "Paused. Logging continues; toasts resume when the pause ends." : "Nothing changed the shape of a session. Normal coding stays silent."
        wrapMode: Text.WordWrap
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      Repeater {
        model: root.rows

        Rectangle {
          id: card
          required property var modelData
          required property int index
          readonly property bool isSelected: root.cursorActive && root.cursor === index
          readonly property bool isHigh: String(modelData.severity || "") === "high"

          width: column.width
          implicitHeight: cardColumn.implicitHeight + Style.spacing.lg * 2
          radius: Style.cornerRadius
          color: isSelected ? root.selectedFill : (cardHover.hovered ? root.hoverFill : "transparent")

          HoverHandler { id: cardHover }

          Column {
            id: cardColumn
            x: Style.spacing.lg
            y: Style.spacing.lg
            width: parent.width - Style.spacing.lg * 2
            spacing: Style.spacing.sm

            Row {
              width: parent.width
              spacing: Style.spacing.md

              OpticalGlyph {
                width: Style.space(18)
                height: Style.space(18)
                text: Model.ruleGlyph(card.modelData)
                fontFamily: root.fontFamily
                fontSize: Style.font.icon
                color: card.isHigh ? root.urgent : root.foreground
              }

              Text {
                width: parent.width - Style.space(18) - timeLabel.implicitWidth - Style.spacing.md * 2
                text: String(card.modelData.summary || card.modelData.rule || "")
                elide: Text.ElideRight
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.weight: card.isHigh ? Font.DemiBold : Font.Normal
              }

              Text {
                id: timeLabel
                text: Model.relativeTime(card.modelData.ts, root.nowMs)
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Text {
              width: parent.width
              text: String(card.modelData.rule || "") + "  ·  " + String(card.modelData.severity || "") + (Model.whereLabel(card.modelData) !== "" ? "  ·  " + Model.whereLabel(card.modelData) : "")
              elide: Text.ElideRight
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Row {
              spacing: Style.spacing.sm

              Button {
                text: Model.isWriteRule(card.modelData) ? "Approve file" : "Approve repo"
                tooltipText: "a"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.approveHere(card.modelData)
              }
              Button {
                text: "Anywhere"
                tooltipText: "A: approve forever"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.approveAnywhere(card.modelData)
              }
              Button {
                visible: card.modelData.pids && card.modelData.pids.length > 0
                text: "Kill"
                tooltipText: "x: confirm in a terminal"
                foreground: root.urgent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.kill(card.modelData)
              }
              Button {
                text: "Investigate"
                tooltipText: "i or Enter"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.investigate(card.modelData)
              }
              Button {
                text: "Dismiss"
                tooltipText: "d"
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
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

      Row {
        width: parent.width
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
        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: "j k move · a approve · x kill · i investigate · d dismiss · p pause"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
