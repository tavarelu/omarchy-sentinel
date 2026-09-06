# D-008: How should a SkillSpector risk score be drawn on an alert card?
Status: DECIDED (Owner, 2026-09-06)
Drafted by: Chief, 2026-09-05, from the UX-04 canvas published at
https://claude.ai/code/artifact/036d35ed-efe5-4160-9bc0-f795721291f8

## Options put to the Owner
- **A. Horizontal bar** with SAFE / CAUTION / DO NOT INSTALL bands and the score as a label. Re-implements
  Omarchy's first-party `Meter` idiom (track plus fill), reads at a glance in a narrow card, costs one row.
- **B. Ring gauge**, the 270-degree dial idiom from `Ui/SpeedTestOverlay.qml`, score centred. More prominent,
  costs noticeably more vertical space per card.

## Decision
**Option A, the bar with SAFE / CAUTION / DO NOT INSTALL bands.**

## Consequences
- `RiskMeter` in `Panel.qml` is a track-plus-fill bar with three bands and a score label; the interim
  track+fill already in the card is the right starting point, so the follow-up stays small.
- Band thresholds follow SkillSpector's own `risk_assessment.recommendation` mapping (SAFE / CAUTION /
  DO_NOT_INSTALL), so the panel never invents a verdict of its own.
- The meter stays hidden while `riskValue(alert)` is -1, which is every alert until W6-01c attaches
  `evidence.scan`.
- Colours come from the existing `Color` tokens (foreground, accent, urgent); there is no amber token on this
  machine, so CAUTION uses a reduced-opacity urgent rather than a new colour.
