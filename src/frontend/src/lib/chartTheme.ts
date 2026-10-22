// Chart colours (dataviz reference palette, dark steps), validated on the card surface #0f172a:
// `validate_palette.js "#3987e5,#d95926" --mode dark --surface "#0f172a"` -> all checks pass.
export const chart = {
  benign: '#3987e5', // categorical slot 1 (blue)
  attack: '#d95926', // categorical slot 2 (orange)
  single: '#3987e5', // single-series charts
  towardAttack: '#e66767', // diverging pole (red)
  towardBenign: '#3987e5', // diverging pole (blue)
  grid: '#1e293b',
  axis: '#334155',
  muted: '#94a3b8',
  text: '#e2e8f0',
  tooltipBg: '#020617',
}

export const axisProps = {
  stroke: chart.axis,
  tick: { fill: chart.muted, fontSize: 12 },
  tickLine: false,
} as const
