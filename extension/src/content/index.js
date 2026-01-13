/**
 * Jetstream - Content Script (MAIN world)
 * Intercepts fetch/WebSocket requests to block sensitive data.
 */

(function() {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════════════
  // CONFIG
  // ═══════════════════════════════════════════════════════════════════════════

  const CONFIG = {
    SSN_PATTERN: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    DEDUPE_TTL_MS: 30000,
    BACKGROUND_TIMEOUT_MS: 10000,
    NOTIFICATION_DURATION_MS: 6000,
    FILE_CACHE_TTL_MS: 5 * 60 * 1000,
    SKIP_URLS: [
      'segment.io', 'segment.com', '/v1/t', '/analytics', '/collect',
      '/log', '/tracking', '/metrics', '/telemetry', 'sentry.io',
    ],
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // STATE
  // ═══════════════════════════════════════════════════════════════════════════

  const state = {
    originalFetch: window.fetch,
    originalWSSend: WebSocket.prototype.send,
    recentlyBlocked: new Set(),
    fileCache: new Map(),
    requestId: 0,
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // UTILS
  // ═══════════════════════════════════════════════════════════════════════════

  const utils = {
    containsSSN(text) {
      CONFIG.SSN_PATTERN.lastIndex = 0;
      return CONFIG.SSN_PATTERN.test(text);
    },

    censorSSNs(text) {
      return text.replace(CONFIG.SSN_PATTERN, '***-**-****');
    },

    async hash(text) {
      const data = new TextEncoder().encode(text);
      const buffer = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE READER
  // ═══════════════════════════════════════════════════════════════════════════

  const fileReader = {
    CLIENT_EXTENSIONS: ['txt', 'csv', 'json', 'md'],
    BACKEND_EXTENSIONS: ['pdf'],

    getExtension(file) {
      return file.name.split('.').pop().toLowerCase();
    },

    async readAsBase64(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    },

    async readAsText(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsText(file);
      });
    },

    async extractText(file) {
      const ext = this.getExtension(file);

      if (this.CLIENT_EXTENSIONS.includes(ext)) {
        return this.readAsText(file);
      }

      if (this.BACKEND_EXTENSIONS.includes(ext)) {
        const base64 = await this.readAsBase64(file);
        const result = await background.extractText(base64, file.name, file.type);
        return result?.text || null;
      }

      return null;
    },

    async cacheFile(file) {
      const content = await this.extractText(file);
      if (content) {
        state.fileCache.set(file.name, content);
        setTimeout(() => state.fileCache.delete(file.name), CONFIG.FILE_CACHE_TTL_MS);
      }
      return content;
    },

    getCached(filename) {
      return state.fileCache.get(filename) || null;
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // BACKGROUND MESSAGING
  // ═══════════════════════════════════════════════════════════════════════════

  const background = {
    send(action, data) {
      return new Promise((resolve, reject) => {
        const id = ++state.requestId;

        const handler = (event) => {
          if (event.detail?.id !== id) return;
          window.removeEventListener('jetstream-from-background', handler);
          event.detail.error ? reject(new Error(event.detail.error)) : resolve(event.detail.response);
        };

        window.addEventListener('jetstream-from-background', handler);
        window.dispatchEvent(new CustomEvent('jetstream-to-background', { detail: { id, action, data } }));

        setTimeout(() => {
          window.removeEventListener('jetstream-from-background', handler);
          reject(new Error('Timeout'));
        }, CONFIG.BACKGROUND_TIMEOUT_MS);
      });
    },

    async isApproved(hash) {
      try {
        const response = await this.send('checkApproval', { hash });
        return response?.approved === true;
      } catch {
        return false;
      }
    },

    async validate(text) {
      try {
        return await this.send('validateText', { text });
      } catch (e) {
        console.error('[Jetstream] Validation error:', e);
        return { has_pii: false, has_secrets: false, detections: [] };
      }
    },

    async extractText(fileData, filename, mimeType) {
      try {
        return await this.send('extractText', { file_data: fileData, filename, mime_type: mimeType });
      } catch (e) {
        console.error('[Jetstream] Text extraction error:', e);
        return null;
      }
    },

    async reportEvent(message, detections, contentHash, contentType = 'prompt') {
      if (state.recentlyBlocked.has(contentHash)) return;

      state.recentlyBlocked.add(contentHash);
      setTimeout(() => state.recentlyBlocked.delete(contentHash), CONFIG.DEDUPE_TTL_MS);

      try {
        await this.send('reportEvent', {
          payload: {
            url: window.location.href,
            domain: window.location.hostname,
            content_type: contentType,
            detection_type: detections.join(', ') || 'PII',
            summary: `Detected: ${detections.join(', ')}`,
            detections: detections.map(d => ({ type: d, masked: '[REDACTED]' })),
            content_hash: contentHash,
            message: utils.censorSSNs(message),
          },
        });
      } catch (e) {
        console.error('[Jetstream] Failed to report:', e);
      }
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // UI
  // ═══════════════════════════════════════════════════════════════════════════

  const ui = {
    showBlockNotification(detections) {
      document.getElementById('jtb-block-banner')?.remove();

      const banner = document.createElement('div');
      banner.id = 'jtb-block-banner';
      banner.innerHTML = `
        <style>
          #jtb-block-banner {
            position: fixed; top: 20px; right: 20px; max-width: 400px;
            background: #dc2626; color: white; padding: 16px 20px; border-radius: 8px;
            z-index: 2147483647; font-family: system-ui, sans-serif;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: jtb-slide 0.3s ease-out;
          }
          @keyframes jtb-slide { from { transform: translateX(100%); opacity: 0; } }
          #jtb-block-banner .jtb-header { font-weight: 600; margin-bottom: 4px; }
          #jtb-block-banner .jtb-dismiss {
            position: absolute; top: 8px; right: 8px;
            background: none; border: none; color: white; cursor: pointer; font-size: 16px;
          }
          #jtb-block-banner .jtb-detections { font-size: 12px; opacity: 0.9; margin-top: 4px; }
        </style>
        <button class="jtb-dismiss" onclick="this.parentElement.remove()">×</button>
        <div class="jtb-header">🛡️ Request Blocked</div>
        <div>Sensitive data detected. Event logged for admin review.</div>
        <div class="jtb-detections">Types: ${detections.join(', ')}</div>
      `;

      document.body.appendChild(banner);
      setTimeout(() => banner.remove(), CONFIG.NOTIFICATION_DURATION_MS);
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // PARSER
  // ═══════════════════════════════════════════════════════════════════════════

  const parser = {
    extractUserMessage(body) {
      if (typeof body !== 'string') return null;
      try {
        const parsed = JSON.parse(body);
        return this._fromChatGPT(parsed) || this._fromClaude(parsed) || null;
      } catch {
        return null;
      }
    },

    _fromChatGPT(parsed) {
      if (!parsed.messages) return null;
      for (let i = parsed.messages.length - 1; i >= 0; i--) {
        const msg = parsed.messages[i];
        if (msg.author?.role === 'user' && msg.content?.parts) {
          const text = msg.content.parts.filter(p => typeof p === 'string' && p.trim()).join(' ');
          return text || null;
        }
        if (msg.role === 'user' && typeof msg.content === 'string') {
          return msg.content.trim() || null;
        }
      }
      return null;
    },

    _fromClaude(parsed) {
      return parsed.prompt || parsed.text || null;
    },

    extractAttachments(body) {
      if (typeof body !== 'string') return [];
      try {
        const parsed = JSON.parse(body);
        if (!parsed.messages) return [];
        for (let i = parsed.messages.length - 1; i >= 0; i--) {
          const msg = parsed.messages[i];
          if (msg.author?.role === 'user' && msg.metadata?.attachments) {
            return msg.metadata.attachments.map(a => ({ name: a.name, type: a.mime_type, id: a.id }));
          }
        }
      } catch {}
      return [];
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // BLOCKER
  // ═══════════════════════════════════════════════════════════════════════════

  const blocker = {
    async checkAndBlock(message) {
      if (!message || message.length < 5) return false;

      const hasSSN = utils.containsSSN(message);
      const validation = await background.validate(message);
      const detections = [...(validation.detections || [])];

      if (hasSSN && !detections.includes('SSN')) {
        detections.unshift('SSN');
      }

      if (!hasSSN && !validation.has_pii && !validation.has_secrets) {
        return false;
      }

      const hash = await utils.hash(message);
      if (await background.isApproved(hash)) {
        console.log('[Jetstream] Message approved, allowing');
        return false;
      }

      console.log('[Jetstream] Blocking - detected:', detections);
      ui.showBlockNotification(detections);
      background.reportEvent(message, detections, hash);
      return true;
    },

    createBlockedResponse() {
      return new Response(JSON.stringify({
        id: 'blocked-' + Date.now(),
        type: 'message',
        content: [{ type: 'text', text: '[Blocked by Jetstream: Sensitive data detected]' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // URL FILTER
  // ═══════════════════════════════════════════════════════════════════════════

  const urlFilter = {
    shouldSkip(url) {
      return CONFIG.SKIP_URLS.some(skip => url.includes(skip));
    },

    isAnalyticsPayload(data) {
      if (typeof data !== 'string') return false;
      try {
        const p = JSON.parse(data);
        return !!(p.integrations || p.writeKey || p.anonymousId ||
                  p.type === 'track' || p.type === 'page' || p.type === 'identify' ||
                  p.events || p.sentAt || p._metadata?.bundled);
      } catch {
        return false;
      }
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERCEPTORS
  // ═══════════════════════════════════════════════════════════════════════════

  function installFetchInterceptor() {
    window.fetch = async function(resource, options = {}) {
      const url = typeof resource === 'string' ? resource : resource?.url || '';

      if (urlFilter.shouldSkip(url)) {
        return state.originalFetch.apply(this, arguments);
      }

      // Handle FormData file uploads
      if (options.body instanceof FormData) {
        for (const [, value] of options.body.entries()) {
          if (value instanceof File) {
            const content = await fileReader.cacheFile(value);
            if (content && await blocker.checkAndBlock(content)) {
              return blocker.createBlockedResponse();
            }
          }
        }
      }

      if (options.method?.toUpperCase() === 'POST' && options.body) {
        const body = typeof options.body === 'string' ? options.body : '';

        if (urlFilter.isAnalyticsPayload(body)) {
          return state.originalFetch.apply(this, arguments);
        }

        // Check cached file attachments
        for (const att of parser.extractAttachments(body)) {
          const cached = fileReader.getCached(att.name);
          if (cached && await blocker.checkAndBlock(cached)) {
            return blocker.createBlockedResponse();
          }
        }

        // Check message text
        const message = parser.extractUserMessage(body);
        if (message && await blocker.checkAndBlock(message)) {
          return blocker.createBlockedResponse();
        }
      }

      return state.originalFetch.apply(this, arguments);
    };
  }

  function installWebSocketInterceptor() {
    WebSocket.prototype.send = function(data) {
      if (urlFilter.isAnalyticsPayload(data)) {
        return state.originalWSSend.apply(this, arguments);
      }

      const message = parser.extractUserMessage(data);
      if (!message || message.length < 5) {
        return state.originalWSSend.apply(this, arguments);
      }

      // Sync SSN check - can block immediately
      if (utils.containsSSN(message)) {
        blocker.checkAndBlock(message);
        console.log('[Jetstream] WebSocket blocked (SSN)');
        return;
      }

      // Async validation - can only warn after send
      background.validate(message).then(async (validation) => {
        if (validation.has_pii || validation.has_secrets) {
          const hash = await utils.hash(message);
          if (await background.isApproved(hash)) return;

          const detections = validation.detections || ['PII'];
          console.warn('[Jetstream] WebSocket sent PII (post-detection):', detections);
          ui.showBlockNotification(detections);
          background.reportEvent(message, detections, hash);
        }
      });

      return state.originalWSSend.apply(this, arguments);
    };
  }

  function installFileInterceptor() {
    document.addEventListener('change', async (event) => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
      if (!input.files?.length) return;

      for (const file of input.files) {
        console.log('[Jetstream] File selected:', file.name);
        await fileReader.cacheFile(file);
      }
    }, true);

    document.addEventListener('drop', async (event) => {
      const files = event.dataTransfer?.files;
      if (!files?.length) return;

      for (const file of files) {
        console.log('[Jetstream] File dropped:', file.name);
        await fileReader.cacheFile(file);
      }
    }, true);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INIT
  // ═══════════════════════════════════════════════════════════════════════════

  function init() {
    installFileInterceptor();
    installFetchInterceptor();
    installWebSocketInterceptor();
    console.log('[Jetstream] Content script loaded');
  }

  init();

})();
