/**
 * Jetstream Takehome - Admin Dashboard
 */

const eventsList = document.getElementById('events-list');
const emptyState = document.getElementById('empty-state');
const modal = document.getElementById('event-modal');
const modalBody = document.getElementById('modal-body');
const modalFooter = document.getElementById('modal-footer');
const modalClose = document.getElementById('modal-close');
const refreshBtn = document.getElementById('refresh-btn');

async function init() {
  refreshBtn.addEventListener('click', loadEvents);
  modalClose.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
  await loadEvents();
}

async function loadEvents() {
  try {
    renderEvents(await api.getEvents());
  } catch {
    eventsList.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#ef4444;">Failed to load. Is backend running?</td></tr>`;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function getTypeBadge(type) {
  const cls = type === 'document' ? 'type-doc' : 'type-prompt';
  return `<span class="type-badge ${cls}">${type || 'prompt'}</span>`;
}

function getDetectionBadge(type) {
  return `<span class="detection-badge">${escapeHtml(type || 'unknown')}</span>`;
}

function renderEvents(events) {
  if (!events.length) {
    eventsList.innerHTML = '';
    emptyState.style.display = 'block';
    return;
  }
  emptyState.style.display = 'none';

  eventsList.innerHTML = events.map(e => `
    <tr data-id="${e.id}" onclick="viewEvent(${e.id})">
      <td>${formatDate(e.created_at)}</td>
      <td title="${escapeHtml(e.url)}">${escapeHtml(e.domain)}</td>
      <td>${getTypeBadge(e.content_type)}</td>
      <td>${getDetectionBadge(e.detection_type)}</td>
      <td><span class="status-badge ${e.status}">${e.status}</span></td>
      <td>
        <button class="action-btn view" onclick="viewEvent(${e.id}); event.stopPropagation();">View</button>
        ${e.status === 'pending' ? `<button class="action-btn approve" onclick="approveEvent(${e.id}); event.stopPropagation();">Approve</button>` : ''}
      </td>
    </tr>
  `).join('');
}

async function viewEvent(id) {
  try {
    const e = await api.getEvent(id);
    const guardrails = e.guardrails_detections?.length ? e.guardrails_detections.join(', ') : 'None';

    modalBody.innerHTML = `
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Timestamp</div>
          <div class="detail-value">${formatDate(e.created_at)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Domain</div>
          <div class="detail-value">${escapeHtml(e.domain)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Content Type</div>
          <div class="detail-value">${getTypeBadge(e.content_type)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Detection Type</div>
          <div class="detail-value">${getDetectionBadge(e.detection_type)}</div>
        </div>
        <div class="detail-item full-width">
          <div class="detail-label">URL</div>
          <div class="detail-value url-value">${escapeHtml(e.url)}</div>
        </div>
        <div class="detail-item full-width">
          <div class="detail-label">Blocked Message</div>
          <div class="detail-value message-box"><pre>${escapeHtml(e.message || 'N/A')}</pre></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Summary</div>
          <div class="detail-value">${escapeHtml(e.summary)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Guardrails AI</div>
          <div class="detail-value">${escapeHtml(guardrails)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Status</div>
          <div class="detail-value"><span class="status-badge ${e.status}">${e.status}</span></div>
        </div>
      </div>
    `;
    modalFooter.innerHTML = e.status === 'pending'
      ? `<button class="action-btn approve" onclick="approveEvent(${e.id})">Approve</button>`
      : `<button class="action-btn view" onclick="closeModal()">Close</button>`;
    modal.style.display = 'flex';
  } catch {
    alert('Failed to load event');
  }
}

function closeModal() {
  modal.style.display = 'none';
}

async function approveEvent(id) {
  try {
    await api.updateEventStatus(id, 'approved');
    closeModal();
    await loadEvents();
  } catch {
    alert('Failed to approve');
  }
}

document.addEventListener('DOMContentLoaded', init);
