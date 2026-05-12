export function createActionRegistry() {
  const handlers = new Map();

  function register(action, handler) {
    handlers.set(action, handler);
  }

  async function dispatch(action, payload) {
    const handler = handlers.get(action);
    if (!handler) return false;
    await handler(payload);
    return true;
  }

  return {
    register,
    dispatch,
  };
}
