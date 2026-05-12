export function createToastController({ t, escapeHtml }) {
  function showToast(message, asKey = true) {
    const toast = document.getElementById("toast");
    toast.classList.remove("toast-check-success");
    toast.hidden = false;
    toast.textContent = asKey ? t(message) : message;
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      toast.hidden = true;
    }, 2800);
  }

  function showRuleSavedNavigationToast() {
    const toast = document.getElementById("toast");
    toast.hidden = false;
    toast.classList.add("toast-check-success");
    toast.innerHTML = `
      <span class="toast-inline">
        <span class="toast-check" aria-hidden="true">✓</span>
        <span>${escapeHtml(t("toast.saved_navigating_rules"))}</span>
      </span>
    `;
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      toast.hidden = true;
      toast.classList.remove("toast-check-success");
      toast.textContent = "";
    }, 2400);
  }

  return {
    showToast,
    showRuleSavedNavigationToast,
  };
}
