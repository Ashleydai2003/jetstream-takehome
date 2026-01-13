/**
 * Jetstream Takehome - Popup Script
 */

const API_BASE_URL = 'http://localhost:8000/api';

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch blocked count from backend
  try {
    const response = await fetch(`${API_BASE_URL}/events`);
    if (response.ok) {
      const data = await response.json();
      document.getElementById('blocked-count').textContent = data.total || 0;
    }
  } catch (error) {
    console.error('[Jetstream] Failed to fetch events:', error);
    document.getElementById('blocked-count').textContent = '?';
  }

  document.getElementById('open-admin').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'http://localhost:3000' });
  });
});
