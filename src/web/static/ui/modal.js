export function askForConfirmation({ t, message, title = "", options = {} }) {
  const dialog = document.getElementById("confirm-dialog");
  const titleNode = document.getElementById("confirm-title");
  const messageNode = document.getElementById("confirm-message");
  const acceptButton = document.getElementById("confirm-accept");
  const cancelButton = document.getElementById("confirm-cancel");

  if (!(dialog instanceof HTMLDialogElement) || !titleNode || !messageNode || !acceptButton || !cancelButton) {
    return Promise.resolve(false);
  }

  const resolvedTitle = String(title || "").trim() || t("common.confirm_action");
  titleNode.textContent = resolvedTitle;
  messageNode.textContent = message;
  acceptButton.textContent = options.acceptLabel || t("common.confirm");
  cancelButton.textContent = options.cancelLabel || t("common.cancel");

  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      acceptButton.removeEventListener("click", onAccept);
      cancelButton.removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancelEvent);
      dialog.removeEventListener("close", onClose);
      resolve(value);
    };

    const onAccept = () => {
      dialog.close("accept");
      finish(true);
    };
    const onCancel = () => {
      dialog.close("cancel");
      finish(false);
    };
    const onCancelEvent = (event) => {
      event.preventDefault();
      dialog.close("cancel");
      finish(false);
    };
    const onClose = () => {
      finish(dialog.returnValue === "accept");
    };

    acceptButton.addEventListener("click", onAccept);
    cancelButton.addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancelEvent);
    dialog.addEventListener("close", onClose);
    dialog.showModal();
  });
}
