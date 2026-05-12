export async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      payload = text;
    }
  }

  if (!response.ok) {
    const error = new Error(payload?.error || payload?.code || response.statusText || "request_failed");
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}
