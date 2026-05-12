export function createToastController({ t, escapeHtml }) {
  function clearToastVariant(toast) {
    toast.classList.remove(
      "toast-check-success",
      "toast-variant-success",
      "toast-variant-error",
      "toast-variant-warning",
    );
  }

  function dismissToast() {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.hidden = true;
    clearToastVariant(toast);
    toast.textContent = "";
  }

  function showToast(message, asKey = true, options = {}) {
    const { variant = "success", timeoutMs = 5000 } = options;
    const timeout = Math.min(
      5000,
      Math.max(0, Number.isFinite(Number(timeoutMs)) ? Number(timeoutMs) : 5000),
    );
    const toast = document.getElementById("toast");
    if (!toast) return;
    clearToastVariant(toast);
    if (variant === "error") {
      toast.classList.add("toast-variant-error");
    } else if (variant === "warning") {
      toast.classList.add("toast-variant-warning");
    } else if (variant === "success") {
      toast.classList.add("toast-variant-success");
    }
    toast.hidden = false;
    const resolvedMessage = asKey ? t(message) : message;
    toast.innerHTML = `
      <span class="toast-inline">
        <span>${escapeHtml(String(resolvedMessage || ""))}</span>
      </span>
      <button type="button" class="toast-close" data-action="toast-close" aria-label="${escapeHtml(t("common.close"))}">x</button>
    `;
    const closeButton = toast.querySelector("[data-action=\"toast-close\"]");
    if (closeButton) {
      closeButton.addEventListener("click", dismissToast, { once: true });
    }
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      dismissToast();
    }, timeout);
  }

  function showRuleSavedNavigationToast() {
    const toast = document.getElementById("toast");
    toast.hidden = false;
    clearToastVariant(toast);
    toast.classList.add("toast-check-success", "toast-variant-success");
    toast.innerHTML = `
      <span class="toast-inline">
        <span class="toast-check" aria-hidden="true">✓</span>
        <span>${escapeHtml(t("toast.saved_navigating_rules"))}</span>
      </span>
      <button type="button" class="toast-close" data-action="toast-close" aria-label="${escapeHtml(t("common.close"))}">x</button>
    `;
    const closeButton = toast.querySelector("[data-action=\"toast-close\"]");
    if (closeButton) {
      closeButton.addEventListener("click", dismissToast, { once: true });
    }
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      dismissToast();
    }, 5000);
  }

  return {
    showToast,
    showRuleSavedNavigationToast,
  };
}
