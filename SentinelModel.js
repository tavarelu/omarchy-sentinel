.pragma library
// SPDX-License-Identifier: Apache-2.0

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

var STICKY_EVENTS = { "foreign-write": true, "alert-log-truncated": true }

function defaultPrefs() {
  return { high: true, medium: true, low: false }
}

// notify-prefs.json is written by `sentinel-action notify`; only the three
// severity flags are honored here, anything else in the file is ignored.
function parsePrefs(text) {
  var prefs = defaultPrefs()
  try {
    var d = JSON.parse(String(text || ""))
    var sev = d && d.severities ? d.severities : {}
    for (var k in prefs) if (typeof sev[k] === "boolean") prefs[k] = sev[k]
  } catch (e) {
    // Missing or corrupt: defaults stand, same as the daemon.
  }
  return prefs
}

function parseBurst(text) {
  try {
    var d = JSON.parse(String(text || ""))
    if (!d || typeof d !== "object") return null
    var total = 0
    var by = d.by_severity || {}
    for (var k in by) total += Number(by[k]) || 0
    return { active: d.active === true, total: total, by: by }
  } catch (e) {
    return null
  }
}

// Tamper alerts are always listed and always toast, whatever the filter says.
function isSticky(a) {
  return a && a.rule === "R-SELF" && a.evidence && STICKY_EVENTS[String(a.evidence.event || "")] === true
}

function severityOn(a, prefs) {
  if (isSticky(a)) return true
  var s = String(a.severity || "")
  if (s === "high" || s === "medium" || s === "low") return prefs[s] !== false
  return true
}

function openAlerts(rows, prefs) {
  var p = prefs || defaultPrefs()
  var out = []
  for (var i = 0; i < rows.length; i++) {
    var a = rows[i]
    if (a.status !== "open") continue
    if (!severityOn(a, p)) continue
    out.push(a)
  }
  // Newest first: the daemon appends in time order.
  out.reverse()
  return out
}

function hiddenCount(rows, prefs) {
  var p = prefs || defaultPrefs()
  var n = 0
  for (var i = 0; i < rows.length; i++) {
    var a = rows[i]
    if (a.status === "open" && !severityOn(a, p)) n++
  }
  return n
}

function severityRank(a) {
  switch (String(a.severity || "")) {
    case "high": return 0
    case "medium": return 1
    case "low": return 2
    default: return 1
  }
}

function severityLabel(a) {
  switch (String(a.severity || "")) {
    case "high": return "HIGH"
    case "medium": return "MED"
    case "low": return "LOW"
    default: return String(a.severity || "").toUpperCase()
  }
}

// SkillSpector result, when a scan is attached: 0..1 or -1 for none.
function riskValue(a) {
  var scan = a && a.evidence ? a.evidence.scan : null
  if (!scan || typeof scan.risk_score !== "number") return -1
  return Math.max(0, Math.min(1, scan.risk_score / 100))
}

function riskVerdict(a) {
  var scan = a && a.evidence ? a.evidence.scan : null
  return scan && scan.verdict ? String(scan.verdict) : ""
}

function fileUri(path) {
  var parts = String(path || "").split("/")
  var out = []
  for (var i = 0; i < parts.length; i++) out.push(encodeURIComponent(parts[i]))
  return "file://" + out.join("/")
}

// argv to reveal the alert's file or open its directory; null when it has neither.
function openArgv(a) {
  if (!a) return null
  if (a.paths && a.paths.length > 0 && String(a.paths[0]).charAt(0) === "/")
    return ["uwsm-app", "--", "nautilus", "--select", fileUri(a.paths[0])]
  if (a.cwd && String(a.cwd).charAt(0) === "/")
    return ["uwsm-app", "--", "nautilus", "--new-window", String(a.cwd)]
  return null
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
