/**
 * Jetstream Takehome - Background Service Worker
 * Handles API calls to backend (bypasses page CSP).
 */

const API_BASE_URL = 'http://localhost:8000/api';

let approvedHashes = new Set();

async function loadApprovedHashes() {
  try {
    const response = await fetch(`${API_BASE_URL}/approvals`);
    const data = await response.json();
    approvedHashes = new Set(data.hashes || []);
  } catch (e) {
    console.error('[Jetstream] Failed to load approvals:', e);
  }
}

async function checkApproval(hash) {
  try {
    const response = await fetch(`${API_BASE_URL}/approvals/check/${hash}`);
    const data = await response.json();
    if (data.approved) approvedHashes.add(hash);
    return data.approved === true;
  } catch {
    return approvedHashes.has(hash);
  }
}

async function reportEvent(payload) {
  try {
    await fetch(`${API_BASE_URL}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function validateText(text) {
  try {
    const response = await fetch(`${API_BASE_URL}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    return await response.json();
  } catch (e) {
    console.error('[Jetstream] Validation failed:', e);
    return { has_pii: false, has_secrets: false, detections: [], error: e.message };
  }
}

async function extractText(fileData, filename, mimeType) {
  try {
    const response = await fetch(`${API_BASE_URL}/extract-text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_data: fileData, filename, mime_type: mimeType })
    });
    return await response.json();
  } catch (e) {
    console.error('[Jetstream] Text extraction failed:', e);
    return { text: '', success: false, error: e.message };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkApproval') {
    checkApproval(message.hash).then(approved => sendResponse({ approved }));
    return true;
  }
  if (message.action === 'reportEvent') {
    reportEvent(message.payload).then(sendResponse);
    return true;
  }
  if (message.action === 'validateText') {
    validateText(message.text).then(sendResponse);
    return true;
  }
  if (message.action === 'extractText') {
    extractText(message.file_data, message.filename, message.mime_type).then(sendResponse);
    return true;
  }
  if (message.action === 'getStatus') {
    sendResponse({ approvedCount: approvedHashes.size });
  }
});

loadApprovedHashes();
setInterval(loadApprovedHashes, 5 * 60 * 1000);

console.log('[Jetstream] Background worker started');
