export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function byId(id) {
  return document.getElementById(id);
}

export function setHidden(node, hidden) {
  if (!node) return;
  node.hidden = Boolean(hidden);
}
