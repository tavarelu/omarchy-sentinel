.pragma library

// Pure helpers for the Sentinel bar widget and panel. No I/O here: the QML
// side reads files and runs commands; this file only turns text into rows.

function parseAlerts(text) {
  var rows = []
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "") continue
    try {
      var a = JSON.parse(line)
      if (a && typeof a === "object" && a.id) rows.push(a)
    } catch (e) {
      // A torn line during a daemon append is expected; skip it.
    }
  }
  return rows
}

function openAlerts(rows, showLow) {
  var out = []
  for (var i = 0; i < rows.length; i++) {
    var a = rows[i]
    if (a.status !== "open") continue
    if (!showLow && String(a.severity || "") === "low") continue
    out.push(a)
  }
  // Newest first: the daemon appends in time order.
  out.reverse()
  return out
}

function countBySeverity(rows) {
  var c = { high: 0, medium: 0, low: 0 }
  for (var i = 0; i < rows.length; i++) {
    var s = String(rows[i].severity || "")
    if (s in c) c[s]++
  }
  return c
}

function basename(path) {
  var s = String(path || "")
  if (s === "") return ""
  var parts = s.split("/")
  for (var i = parts.length - 1; i >= 0; i--) if (parts[i] !== "") return parts[i]
  return s
}

function whereLabel(a) {
  if (a.cwd) return basename(a.cwd)
  if (a.paths && a.paths.length > 0) return basename(a.paths[0])
  return ""
}

function isWriteRule(a) {
  return a.rule === "R-HOOK-WRITE" || a.rule === "R-SELF"
}

function ruleGlyph(a) {
  switch (String(a.rule || "")) {
    case "R-BYPASS": return "󰈸"
    case "R-CHILD-SHELL": return "󰆍"
    case "R-HOOK-WRITE": return "󰈔"
    case "R-SELF": return "󰒃"
    case "R-ALLOW-EXPIRE": return "󰔟"
    default: return "󰀪"
  }
}

function relativeTime(iso, nowMs) {
  var t = new Date(String(iso || "")).getTime()
  if (!isFinite(t)) return ""
  var s = Math.max(0, Math.round((nowMs - t) / 1000))
  if (s < 60) return s + "s ago"
  var m = Math.round(s / 60)
  if (m < 60) return m + "m ago"
  var h = Math.round(m / 60)
  if (h < 48) return h + "h ago"
  return Math.round(h / 24) + "d ago"
}

function parsePauseUntil(text) {
  var raw = String(text || "").trim()
  if (raw === "") return 0
  var t = new Date(raw).getTime()
  return isFinite(t) ? t : 0
}
