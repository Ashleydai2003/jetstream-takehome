/**
 * Jetstream Takehome - Bridge Script (ISOLATED world)
 * Relays messages between MAIN world and background service worker.
 */

window.addEventListener('jetstream-to-background', async (event) => {
  const { id, action, data } = event.detail;
  try {
    const response = await chrome.runtime.sendMessage({ action, ...data });
    window.dispatchEvent(new CustomEvent('jetstream-from-background', { detail: { id, response } }));
  } catch (e) {
    window.dispatchEvent(new CustomEvent('jetstream-from-background', { detail: { id, error: e.message } }));
  }
});
