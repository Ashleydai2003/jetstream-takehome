/**
 * Jetstream - Content Script (MAIN world)
 * Intercepts fetch and WebSocket requests to block sensitive data using Guardrails AI.
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
    // Skip these paths (analytics, telemetry, etc.)
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
    requestId: 0,
    // Cache file contents keyed by filename (for when conversation references them later)
    fileCache: new Map(),
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // UTILS
  // ═══════════════════════════════════════════════════════════════════════════
  
  const utils = {
    /** Check if text contains any SSN patterns (fast client-side check) */
    containsSSN(text) {
      CONFIG.SSN_PATTERN.lastIndex = 0;
      return CONFIG.SSN_PATTERN.test(text);
    },

    /** Replace SSNs with masked version */
    censorSSNs(text) {
      return text.replace(CONFIG.SSN_PATTERN, '***-**-****');
    },

    /** Generate SHA-256 hash of content */
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
    // Extensions we can read client-side
    CLIENT_EXTENSIONS: ['txt', 'csv', 'json', 'md'],
    // Extensions we send to backend for extraction
    BACKEND_EXTENSIONS: ['pdf'],

    isClientSupported(file) {
      const ext = file.name.split('.').pop().toLowerCase();
      return this.CLIENT_EXTENSIONS.includes(ext);
    },

    isBackendSupported(file) {
      const ext = file.name.split('.').pop().toLowerCase();
      return this.BACKEND_EXTENSIONS.includes(ext);
    },

    /** Read file as base64 for sending to backend */
    async readAsBase64(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const base64 = reader.result.split(',')[1]; // Remove data URL prefix
          resolve(base64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    },

    /** Extract text client-side for supported types */
    async extractTextClient(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsText(file);
      });
    },

    /** Extract text from file (client-side or via backend) */
    async extractText(file) {
      if (this.isClientSupported(file)) {
        return await this.extractTextClient(file);
      }
      if (this.isBackendSupported(file)) {
        const base64 = await this.readAsBase64(file);
        const result = await background.extractText(base64, file.name, file.type);
        return result?.text || null;
      }
      return null;
    },

    /** Cache file content for later lookup when conversation references it */
    async cacheFile(file) {
      const content = await this.extractText(file);
      if (content) {
        state.fileCache.set(file.name, content);
        // Auto-expire after 5 minutes
        setTimeout(() => state.fileCache.delete(file.name), 5 * 60 * 1000);
      }
      return content;
    },

    /** Get cached file content by filename */
    getCached(filename) {
      return state.fileCache.get(filename) || null;
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // BACKGROUND MESSAGING
  // ═══════════════════════════════════════════════════════════════════════════
  
  const background = {
    /** Send message to background script via bridge */
    send(action, data) {
      return new Promise((resolve, reject) => {
        const id = ++state.requestId;
        
        const handler = (event) => {
          if (event.detail?.id !== id) return;
          window.removeEventListener('jetstream-from-background', handler);
          event.detail.error 
            ? reject(new Error(event.detail.error)) 
            : resolve(event.detail.response);
        };

        window.addEventListener('jetstream-from-background', handler);
        window.dispatchEvent(new CustomEvent('jetstream-to-background', { 
          detail: { id, action, data } 
        }));

        setTimeout(() => {
          window.removeEventListener('jetstream-from-background', handler);
          reject(new Error('Timeout'));
        }, CONFIG.BACKGROUND_TIMEOUT_MS);
      });
    },

    /** Check if content hash is approved */
    async isApproved(hash) {
      try {
        const response = await this.send('checkApproval', { hash });
        return response?.approved === true;
      } catch {
        return false;
      }
    },

    /** Validate text using Guardrails AI on backend */
    async validate(text) {
      try {
        const response = await this.send('validateText', { text });
        return response;
      } catch (e) {
        console.error('[Jetstream] Validation error:', e);
        // Fall back to client-side SSN check only
        return { has_pii: false, has_secrets: false, detections: [] };
      }
    },

    /** Extract text from file via backend (for PDFs, etc.) */
    async extractText(fileData, filename, mimeType) {
      try {
        const response = await this.send('extractText', { file_data: fileData, filename, mime_type: mimeType });
        return response;
      } catch (e) {
        console.error('[Jetstream] Text extraction error:', e);
        return null;
      }
    },

    /** Report blocked event to backend */
    async reportEvent(message, detections, contentHash, contentType = 'prompt') {
      if (state.recentlyBlocked.has(contentHash)) return;
      
      state.recentlyBlocked.add(contentHash);
      setTimeout(() => state.recentlyBlocked.delete(contentHash), CONFIG.DEDUPE_TTL_MS);

      const detectionType = detections.join(', ') || 'PII';
      
      try {
        await this.send('reportEvent', {
          payload: {
            url: window.location.href,
            domain: window.location.hostname,
            content_type: contentType,
            detection_type: detectionType,
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
  // UI NOTIFICATIONS
  // ═══════════════════════════════════════════════════════════════════════════
  
  const ui = {
    /** Show block notification banner */
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
          #jtb-block-banner .jtb-detections {
            font-size: 12px; opacity: 0.9; margin-top: 4px;
        }
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
  // MESSAGE PARSING
  // ═══════════════════════════════════════════════════════════════════════════
  
  const parser = {
    /** Extract user message from request body (handles ChatGPT & Claude formats) */
    extractUserMessage(body) {
      if (typeof body !== 'string') return null;

      try {
        const parsed = JSON.parse(body);
        return this._extractFromChatGPT(parsed) || this._extractFromClaude(parsed) || null;
      } catch {
        return null; // Don't fall back to raw body - it's not a user message
      }
    },

    /** ChatGPT format: { messages: [{ author: { role }, content: { parts } }] } */
    _extractFromChatGPT(parsed) {
      if (!parsed.messages) return null;

      for (let i = parsed.messages.length - 1; i >= 0; i--) {
        const msg = parsed.messages[i];
        if (msg.author?.role === 'user' && msg.content?.parts) {
          const text = msg.content.parts.filter(p => typeof p === 'string' && p.trim()).join(' ');
          return text || null; // Return null if empty, don't fall back to raw body
        }
        if (msg.role === 'user' && typeof msg.content === 'string') {
          return msg.content.trim() || null;
        }
      }
      return null;
    },

    /** Claude format: { prompt: "..." } or { text: "..." } */
    _extractFromClaude(parsed) {
      if (typeof parsed.prompt === 'string') return parsed.prompt;
      if (typeof parsed.text === 'string') return parsed.text;
      return null;
    },

    /** Extract file attachments from ChatGPT request body */
    extractAttachments(body) {
      if (typeof body !== 'string') return [];
      try {
        const parsed = JSON.parse(body);
        if (!parsed.messages) return [];
        for (let i = parsed.messages.length - 1; i >= 0; i--) {
          const msg = parsed.messages[i];
          if (msg.author?.role === 'user' && msg.metadata?.attachments) {
            return msg.metadata.attachments.map(a => ({
              name: a.name,
              type: a.mime_type,
              id: a.id,
            }));
          }
        }
        return [];
      } catch {
        return [];
      }
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // BLOCKING LOGIC
  // ═══════════════════════════════════════════════════════════════════════════
  
  const blocker = {
    /** Check message and block if contains PII. Returns true if blocked. */
    async checkAndBlock(message) {
      if (!message || message.length < 5) return false;

      // First, fast client-side SSN check
      const hasSSN = utils.containsSSN(message);
      
      // Then, call backend for full Guardrails validation
      const validation = await background.validate(message);
      
      // Combine detections
      const detections = [...(validation.detections || [])];
      if (hasSSN && !detections.includes('SSN')) {
        detections.unshift('SSN');
      }

      // If no PII/secrets found, allow
      if (!hasSSN && !validation.has_pii && !validation.has_secrets) {
        return false;
      }

      // Check if already approved
      const hash = await utils.hash(message);
      if (await background.isApproved(hash)) {
        console.log('[Jetstream] Message approved, allowing');
        return false;
      }

      // Block and report
      console.log('[Jetstream] Blocking - detected:', detections);
      ui.showBlockNotification(detections);
      background.reportEvent(message, detections, hash);
      return true;
    },

    /** Create a blocked response for fetch interception */
    createBlockedResponse() {
      return new Response(JSON.stringify({
        id: 'blocked-' + Date.now(),
        type: 'message',
        content: [{ type: 'text', text: '[Blocked by Jetstream: Sensitive data detected]' }],
      }), { 
        status: 200, 
        headers: { 'Content-Type': 'application/json' } 
      });
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // URL FILTERING
  // ═══════════════════════════════════════════════════════════════════════════

  const urlFilter = {
    /** Check if URL should be skipped (analytics/telemetry) */
    shouldSkipUrl(url) {
      return CONFIG.SKIP_URLS.some(skip => url.includes(skip));
    },

    /** Check if payload is analytics/telemetry (not a chat message) */
    isAnalyticsPayload(data) {
      if (typeof data !== 'string') return false;
      try {
        const parsed = JSON.parse(data);
        // Analytics payloads have these telemetry fields
        return !!(parsed.integrations || parsed.writeKey || parsed.anonymousId || 
                  parsed.type === 'track' || parsed.type === 'page' || parsed.type === 'identify' ||
                  parsed.events || parsed.sentAt || parsed._metadata?.bundled);
      } catch {
        return false;
      }
    },
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERCEPTORS
  // ═══════════════════════════════════════════════════════════════════════════
  
  /** Override fetch for ChatGPT interception */
  function installFetchInterceptor() {
    window.fetch = async function(resource, options = {}) {
      const url = typeof resource === 'string' ? resource : resource?.url || '';

      // Skip analytics/telemetry URLs
      if (urlFilter.shouldSkipUrl(url)) {
        return state.originalFetch.apply(this, arguments);
      }

      // Cache files when FormData uploads happen (before they're sent to ChatGPT)
      if (options.body instanceof FormData) {
        for (const [, value] of options.body.entries()) {
          if (value instanceof File) {
            const content = await fileReader.cacheFile(value);
            // Also validate file content immediately
            if (content && await blocker.checkAndBlock(content)) {
              return blocker.createBlockedResponse();
            }
          }
        }
      }

      if (options.method?.toUpperCase() === 'POST' && options.body) {
        const body = typeof options.body === 'string' ? options.body : '';

        // Skip analytics payloads (check body content)
        if (urlFilter.isAnalyticsPayload(body)) {
          return state.originalFetch.apply(this, arguments);
        }

        // Check for file attachments in conversation request
        const attachments = parser.extractAttachments(body);
        if (attachments.length > 0) {
          // Look up cached file content and validate
          for (const att of attachments) {
            const cachedContent = fileReader.getCached(att.name);
            if (cachedContent && await blocker.checkAndBlock(cachedContent)) {
              return blocker.createBlockedResponse();
            }
          }
        }

        // Also validate text message
        const message = parser.extractUserMessage(body);
        if (message && await blocker.checkAndBlock(message)) {
          return blocker.createBlockedResponse();
        }
      }
      return state.originalFetch.apply(this, arguments);
    };
  }

  /** Override WebSocket.send for Claude interception */
  function installWebSocketInterceptor() {
    WebSocket.prototype.send = function(data) {
      // Skip analytics payloads
      if (urlFilter.isAnalyticsPayload(data)) {
        return state.originalWSSend.apply(this, arguments);
      }

      const message = parser.extractUserMessage(data);
      if (!message || message.length < 5) {
        return state.originalWSSend.apply(this, arguments);
      }

      // For WebSocket, we need sync check. Do fast SSN check first.
      if (utils.containsSSN(message)) {
        blocker.checkAndBlock(message);
        console.log('[Jetstream] WebSocket message blocked (SSN)');
        return;
      }

      // For non-SSN PII, we can't block sync. Validate async and warn.
      background.validate(message).then(async (validation) => {
        if (validation.has_pii || validation.has_secrets) {
          const hash = await utils.hash(message);
          if (await background.isApproved(hash)) return;
          
          const detections = validation.detections || ['PII'];
          console.warn('[Jetstream] WebSocket sent PII (detected after send):', detections);
          ui.showBlockNotification(detections);
          background.reportEvent(message, detections, hash);
        }
      });

      return state.originalWSSend.apply(this, arguments);
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE INPUT INTERCEPTION
  // ═══════════════════════════════════════════════════════════════════════════

  function installFileInterceptor() {
    // Intercept file input selection
    document.addEventListener('change', async (event) => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
      if (!input.files || input.files.length === 0) return;

      for (const file of input.files) {
        console.log('[Jetstream] File selected:', file.name, file.type);
        const content = await fileReader.cacheFile(file);
        if (content) {
          console.log('[Jetstream] Cached file:', file.name, content.length, 'chars');
        }
      }
    }, true);

    // Intercept drag-and-drop
    document.addEventListener('drop', async (event) => {
      const files = event.dataTransfer?.files;
      if (!files || files.length === 0) return;

      for (const file of files) {
        console.log('[Jetstream] File dropped:', file.name);
        const content = await fileReader.cacheFile(file);
        if (content) {
          console.log('[Jetstream] Cached dropped file:', file.name, content.length, 'chars');
        }
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
    console.log('[Jetstream] Content script loaded (files + fetch + WebSocket)');
  }

  init();

})();
