/**
 * Jetstream Takehome - Admin API Client
 */

const API_BASE_URL = 'http://localhost:8000/api';

const api = {
  async getEvents() {
    const res = await fetch(`${API_BASE_URL}/events`);
    if (!res.ok) throw new Error('Failed to fetch events');
    return (await res.json()).items || [];
  },

  async getEvent(id) {
    const res = await fetch(`${API_BASE_URL}/events/${id}`);
    if (!res.ok) throw new Error('Failed to fetch event');
    return res.json();
  },

  async updateEventStatus(id, status) {
    const res = await fetch(`${API_BASE_URL}/events/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    if (!res.ok) throw new Error('Failed to update event');
    return res.json();
  }
};
