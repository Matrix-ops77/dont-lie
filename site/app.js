/* ============================================================
   DON'T-LIE · app.js
   Real Ed25519 receipt chain running in the browser.
   ============================================================ */

(() => {
  'use strict';

  // ============================================================
  // CRYPTO PRIMITIVES
  // ============================================================
  const enc = new TextEncoder();

  function hex(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, '0');
    return s;
  }

  function hexShort(s, n = 10) {
    if (!s) return s;
    if (s.length <= n * 2) return s;
    return s.slice(0, n) + '…';
  }

  async function sha256(text) {
    const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
    return hex(buf);
  }

  // Canonical JSON: sorted keys, no whitespace
  function canon(obj) {
    if (obj === null) return 'null';
    if (typeof obj === 'number') return String(obj);
    if (typeof obj === 'string') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(canon).join(',') + ']';
    if (typeof obj === 'object') {
      const keys = Object.keys(obj).sort();
      return '{' + keys.map(k => JSON.stringify(k) + ':' + canon(obj[k])).join(',') + '}';
    }
    throw new Error('non-serializable');
  }

  // ============================================================
  // ED25519 KEY (cached for the session)
  // ============================================================
  let OPERATOR_KEY = null;
  let OPERATOR_KEY_ID = null;
  let OPERATOR_PUB_HEX = null;

  async function generateKey() {
    const kp = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    );
    const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
    const pubHex = hex(rawPub);
    const keyId = pubHex.slice(0, 16);
    return { kp, keyId, pubHex };
  }

  async function getKey() {
    if (OPERATOR_KEY) return { kp: OPERATOR_KEY, keyId: OPERATOR_KEY_ID, pubHex: OPERATOR_PUB_HEX };
    const k = await generateKey();
    OPERATOR_KEY = k.kp;
    OPERATOR_KEY_ID = k.keyId;
    OPERATOR_PUB_HEX = k.pubHex;
    return k;
  }

  async function sign(canonicalText) {
    const { kp } = await getKey();
    const sig = await crypto.subtle.sign('Ed25519', kp.privateKey, enc.encode(canonicalText));
    return hex(sig);
  }

  async function verify(canonicalText, sigHex) {
    const { kp } = await getKey();
    const sig = new Uint8Array(sigHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    return crypto.subtle.verify('Ed25519', kp.publicKey, sig, enc.encode(canonicalText));
  }

  // ============================================================
  // RECEIPT FACTORY
  // ============================================================
  const MODELS = [
    'MiniMax-M3',
    'claude-opus-4-1',
    'gpt-4.1',
    'llama-3.3-70b',
    'mistral-large-2',
    'qwen-2.5-coder-32b',
  ];
  const PROMPTS = [
    'Summarize the Q2 risk report, return only JSON.',
    'Classify this support ticket, return category + severity.',
    'Extract entities, return as JSON-LD.',
    'Draft a 3-paragraph response to a HIPAA access request.',
    'Review the loan file for red flags, return a checklist.',
    'Translate this deposition excerpt, preserve speaker tags.',
    'Parse the lab report and flag out-of-range values.',
    'Redact PII from the email thread, return the clean version.',
  ];
  const RESPONSES = [
    '{"summary":"Q2 net new ARR: $4.7M, up 18% QoQ","risks":["churn ↑ 2pp","pipeline coverage 3.1x"]}',
    '{"category":"billing","severity":"P3","action":"route to L2"}',
    '{"entities":[{"name":"Solera Legal LLP","type":"org","role":"plaintiff"}]}',
    'Dear Records Custodian, I am writing on behalf of…',
    '["Concentration in single counterparty > 25%","DSCR below 1.15x","Missing 2024 tax return"]',
    '[Speaker 1] I told the underwriter on March 4 that…',
    'Notable: glucose 212 mg/dL (H), creatinine 1.6 (H).',
    'Subject line redacted. Body redacted except [PERSON_A] and [PERSON_B] references.',
  ];

  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  let tamperOffset = null;
  let tamperOrig = null;

  async function buildReceipt(parentSha, idx) {
    const id = idx;
    const issued_at = new Date().toISOString();
    const model = pick(MODELS);
    const endpoint = '/v1/chat/completions';
    const prompt = pick(PROMPTS);
    const response = pick(RESPONSES);
    const { keyId, pubHex } = await getKey();

    // payload_sha256 = SHA-256(canonical({prompt, response, model, endpoint}))
    const payload_canon = canon({ prompt, response, model, endpoint });
    const payload_sha256 = await sha256(payload_canon);

    // Build the unsigned body — exactly what gets signed
    const body = {
      id,
      issued_at,
      model,
      endpoint,
      payload_sha256,
      parent_sha256: parentSha,
      operator_key_id: keyId,
      operator_pub_sha256: await sha256(pubHex),
    };
    const canonical = canon(body);
    const body_sha256 = await sha256(canonical);
    const signature = await sign(canonical);

    const receipt = {
      ...body,
      body_sha256,
      signature,
      // stashed for the demo (would not be in a real receipt; for visualization only)
      _display: { prompt, response }
    };

    return { receipt, payload_canon, body_canon: canonical };
  }

  // ============================================================
  // CHAIN STATE
  // ============================================================
  const state = {
    receipts: [],   // array of { receipt, payload_canon, body_canon, tampered }
    active: -1,     // index of active receipt in panel
    liveCount: 0,
  };

  async function buildChain(n = 4) {
    state.receipts = [];
    let parent = null;
    for (let i = 1; i <= n; i++) {
      const { receipt, payload_canon, body_canon } = await buildReceipt(parent, i);
      state.receipts.push({ receipt, payload_canon, body_canon, tampered: false });
      parent = receipt.body_sha256;
    }
    state.active = state.receipts.length - 1;
  }

  // ============================================================
  // VERIFICATION
  // ============================================================
  async function checkOne(idx) {
    const { receipt, body_canon, tampered } = state.receipts[idx];
    if (tampered) {
      return { ok: false, reason: 'payload modified (signature mismatch)' };
    }
    // signature
    const sigValid = await verify(body_canon, receipt.signature);
    if (!sigValid) return { ok: false, reason: 'signature invalid' };
    // parent link
    if (idx === 0) {
      if (receipt.parent_sha256 !== null) return { ok: false, reason: 'genesis has unexpected parent' };
    } else {
      const prev = state.receipts[idx - 1];
      if (prev.tampered) return { ok: false, reason: 'parent receipt tampered' };
      if (receipt.parent_sha256 !== prev.receipt.body_sha256) {
        return { ok: false, reason: 'parent_sha256 does not match previous receipt' };
      }
    }
    return { ok: true };
  }

  async function checkAll() {
    const results = [];
    for (let i = 0; i < state.receipts.length; i++) {
      results.push(await checkOne(i));
    }
    return results;
  }

  // ============================================================
  // RENDER
  // ============================================================
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.from(document.querySelectorAll(sel));

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') e.className = v;
      else if (k === 'html') e.innerHTML = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') {
        e.addEventListener(k.slice(2).toLowerCase(), v);
      } else {
        e.setAttribute(k, v);
      }
    }
    for (const c of children) {
      if (c == null) continue;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return e;
  }

  function renderChainList() {
    const list = $('#chainList');
    list.innerHTML = '';

    const head = el('div', { class: 'chain-list__head' },
      el('span', { text: 'chain · ' + state.receipts.length + ' receipts' }),
      el('span', { text: 'depth ' + state.receipts.length })
    );
    list.appendChild(head);

    state.receipts.forEach((r, i) => {
      const active = i === state.active;
      const tampered = r.tampered;
      const cls = 'chain-row' + (active ? ' chain-row--active' : '') + (tampered ? ' chain-row--tampered' : '');
      const row = el('div', { class: cls, onClick: () => { state.active = i; renderAll(); } },
        el('span', { class: 'chain-row__num', text: '#' + r.receipt.id }),
        el('span', { class: 'chain-row__hash', text: hexShort(r.receipt.body_sha256, 12) }),
        el('span', {
          class: 'chain-row__badge ' + (tampered ? 'chain-row__badge--bad' : (active ? 'chain-row__badge--active' : 'chain-row__badge--ok')),
          text: tampered ? 'tampered' : (active ? 'viewing' : 'ok')
        })
      );
      list.appendChild(row);
    });
  }

  function renderActive() {
    if (state.active < 0) return;
    const { receipt, tampered } = state.receipts[state.active];

    $('#rcptId').textContent = '#' + receipt.id;
    $('#rcptTs').textContent = receipt.issued_at;
    const modelEl = $('#rcptModel');
    modelEl.textContent = receipt.model;
    modelEl.classList.toggle('bad-field', tampered);
    $('#rcptParent').textContent = receipt.parent_sha256 ? hexShort(receipt.parent_sha256, 14) : '— (genesis)';
    $('#rcptSha').textContent = hexShort(receipt.payload_sha256, 14);
    $('#rcptSig').textContent = hexShort(receipt.signature, 14);
    $('#rcptKey').textContent = receipt.operator_key_id;

    const card = $('#activeReceipt');
    card.dataset.state = tampered ? 'bad' : 'ok';
    const verdict = $('#rcptVerdict');
    verdict.textContent = tampered ? 'TAMPERED' : 'VERIFIED';
  }

  async function renderVerify() {
    const checks = $('#verifyChecks');
    checks.innerHTML = '';
    const results = await checkAll();
    const card = $('#verifyCard');
    const sub = $('#verifySub');

    const fail = results.findIndex(r => !r.ok);
    if (fail === -1) {
      card.dataset.state = 'ok';
      sub.textContent = `all ${state.receipts.length} receipts intact, signatures valid, parent links unbroken`;
    } else {
      card.dataset.state = 'bad';
      const where = `#${state.receipts[fail].receipt.id}`;
      const reason = results[fail].reason;
      sub.textContent = `verification failed at ${where} — ${reason}`;
    }

    results.forEach((r, i) => {
      const r_ = state.receipts[i];
      const li = el('li', { class: r.ok ? '' : 'fail' },
        el('span', { class: 'icon', html: r.ok
          ? '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5L20 7"/></svg>'
          : '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12"/><path d="M18 6L6 18"/></svg>'
        }),
        el('span', { text: `#${r_.receipt.id}  signature & parent link` }),
        el('span', { class: 'badge', text: r.ok ? 'OK' : (r.reason || 'FAIL') })
      );
      checks.appendChild(li);
    });
  }

  function renderAll() {
    renderChainList();
    renderActive();
    renderVerify();
  }

  // ============================================================
  // TAMPER ACTION
  // ============================================================
  function tamperOne() {
    if (state.active < 0) return;
    const r = state.receipts[state.active];
    if (r.tampered) return;

    // Flip one character in the model field
    const orig = r.receipt.model;
    const arr = orig.split('');
    // pick a non-space char to change
    let idx = 0;
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] !== ' ' && arr[i] !== '-') { idx = i; break; }
    }
    // mutate a character (case or letter change)
    const ch = arr[idx];
    let next;
    if (ch === ch.toLowerCase()) next = ch.toUpperCase();
    else next = ch.toLowerCase();
    if (next === ch) next = ch === 'a' ? 'b' : 'a';
    arr[idx] = next;
    r.receipt.model = arr.join('');
    r.tampered = true;
    tamperOffset = idx;
    tamperOrig = orig;

    renderAll();
  }

  async function regenerate() {
    await buildChain(4);
    renderAll();
    flashToast('chain regenerated · ' + state.receipts.length + ' fresh receipts');
  }

  function exportBundle() {
    const bundle = state.receipts.map(r => {
      const { _display, ...rest } = r.receipt;
      return rest;
    });
    const jsonl = bundle.map(b => JSON.stringify(b)).join('\n');
    const blob = new Blob([jsonl + '\n'], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'dontlie-receipts.bundle.jsonl';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    flashToast('exported ' + state.receipts.length + ' receipts as JSONL bundle');
  }

  // ============================================================
  // LIVE FEED (hero)
  // ============================================================
  const feed = $('#feedBody');
  let feedSeq = 0;
  const MAX_FEED = 6;

  function feedRow() {
    const id = ++feedSeq;
    const fakeHash = hex(crypto.getRandomValues(new Uint8Array(32)));
    return el('div', { class: 'feed-row' },
      el('span', { class: 'feed-row__id', text: '#' + (1000 + id) }),
      el('span', { class: 'feed-row__hash', text: hexShort(fakeHash, 12) }),
      el('span', { class: 'feed-row__sig', text: 'signed' })
    );
  }

  function tickFeed() {
    const row = feedRow();
    feed.prepend(row);
    while (feed.children.length > MAX_FEED) feed.lastChild.remove();
    state.liveCount++;
    $('#liveCount').textContent = state.liveCount.toLocaleString();
  }

  function tickClock() {
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    $('#feedTime').textContent =
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  // ============================================================
  // TOAST
  // ============================================================
  function flashToast(msg) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    const t = el('div', {
      class: 'toast',
      text: msg
    });
    Object.assign(t.style, {
      position: 'fixed',
      bottom: '2rem',
      left: '50%',
      transform: 'translateX(-50%) translateY(20px)',
      padding: '0.75rem 1.25rem',
      background: 'rgba(8, 8, 10, 0.95)',
      border: '1px solid var(--line-2)',
      borderRadius: '12px',
      color: 'var(--fg-0)',
      fontSize: '0.85rem',
      fontFamily: 'var(--font-mono)',
      boxShadow: '0 20px 60px -20px rgba(0,0,0,0.7)',
      backdropFilter: 'blur(20px)',
      zIndex: '200',
      opacity: '0',
      transition: 'opacity 0.3s, transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
      pointerEvents: 'none',
    });
    document.body.appendChild(t);
    requestAnimationFrame(() => {
      t.style.opacity = '1';
      t.style.transform = 'translateX(-50%) translateY(0)';
    });
    setTimeout(() => {
      t.style.opacity = '0';
      t.style.transform = 'translateX(-50%) translateY(20px)';
      setTimeout(() => t.remove(), 300);
    }, 2400);
  }

  // ============================================================
  // INSTALL TERMINAL — typewriter
  // ============================================================
  function animateTerminal() {
    const block = $('#installBlock');
    if (!block) return;
    // already filled; just gentle shimmer
    block.style.opacity = '1';
  }

  // ============================================================
  // SCROLL REVEAL
  // ============================================================
  function setupReveal() {
    if (!('IntersectionObserver' in window)) return;
    const targets = $$('.section, .problem-card, .proof-card, .bento__cell, .plan, .compliance-card, .tamper');
    targets.forEach(t => t.setAttribute('data-reveal', ''));
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('is-revealed');
          io.unobserve(e.target);
        }
      });
    }, { rootMargin: '0px 0px -10% 0px', threshold: 0.05 });
    targets.forEach(t => io.observe(t));
  }

  // ============================================================
  // COPY INSTALL
  // ============================================================
  function setupCopy() {
    const btn = $('#copyInstall');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText('pip install dontlie');
        const orig = btn.textContent;
        btn.textContent = 'copied';
        btn.style.color = 'var(--ok)';
        btn.style.borderColor = 'var(--ok)';
        setTimeout(() => {
          btn.textContent = orig;
          btn.style.color = '';
          btn.style.borderColor = '';
        }, 1500);
      } catch (e) { /* ignore */ }
    });
  }

  // ============================================================
  // NAV
  // ============================================================
  function setupNav() {
    const menu = $('#navMenu');
    const links = $('.nav__links');
    if (!menu) return;
    menu.addEventListener('click', () => {
      const open = links.classList.toggle('is-open');
      menu.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        Object.assign(links.style, {
          display: 'flex',
          position: 'absolute',
          top: '100%',
          left: '0',
          right: '0',
          flexDirection: 'column',
          background: 'var(--bg-1)',
          padding: '1rem',
          borderBottom: '1px solid var(--line-2)',
          gap: '0.75rem',
          zIndex: '60',
        });
      } else {
        links.removeAttribute('style');
      }
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(a => {
      a.addEventListener('click', e => {
        const href = a.getAttribute('href');
        if (href.length > 1) {
          const target = document.querySelector(href);
          if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            // collapse mobile menu if open
            if (links.classList.contains('is-open')) menu.click();
          }
        }
      });
    });
  }

  // ============================================================
  // BUTTON HOVER (magnetic-ish)
  // ============================================================
  function setupMagnetic() {
    const buttons = $$('.btn--primary, .btn--lg.btn--outline');
    buttons.forEach(btn => {
      btn.addEventListener('mousemove', e => {
        const r = btn.getBoundingClientRect();
        const x = e.clientX - r.left - r.width / 2;
        const y = e.clientY - r.top - r.height / 2;
        btn.style.transform = `translate(${x * 0.08}px, ${y * 0.15}px) translateY(-1px)`;
      });
      btn.addEventListener('mouseleave', () => {
        btn.style.transform = '';
      });
    });
  }

  // ============================================================
  // VERIFY URL: decode a self-contained verify URL and render
  // ============================================================
  function b64urlDecodeBytes(s) {
    // Re-add stripped padding, swap URL-safe chars, atob
    const pad = '='.repeat((-s.length) % 4);
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  function b64urlDecodeText(s) {
    return new TextDecoder().decode(b64urlDecodeBytes(s));
  }
  function b64DecodeBytes(s) {
    const bin = atob(s);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  async function importEd25519FromPem(pem) {
    // Ed25519 public keys in PEM are PKCS#8 / SPKI wrapped.
    // Strip the headers/footers + whitespace, base64-decode, skip the
    // 12-byte SPKI prefix, and import the remaining 32 raw bytes.
    const lines = pem.split('\n').filter(l => !l.trim().startsWith('-----'));
    const b64 = lines.join('').replace(/\s+/g, '');
    const der = b64DecodeBytes(b64);
    const raw = der.slice(12);
    if (raw.length !== 32) {
      throw new Error('public key is not 32 bytes after SPKI strip (got ' + raw.length + ')');
    }
    return crypto.subtle.importKey(
      'raw', raw,
      { name: 'Ed25519' },
      true,
      ['verify']
    );
  }

  // Build the canonical payload for a single receipt (matches the
  // Python signer's _canonical_payload in dontlie/storage.py).
  function canonicalReceiptPayload(rec) {
    const chainVersion = (rec.extra || {})['_dontlie_chain_version'];
    const obj = {
      id: rec.id,
      timestamp: rec.timestamp,
      model: rec.model,
      prompt: rec.prompt,
      response: rec.response,
      parent_id: rec.parent_id,
      key_id: rec.key_id,
      tags: rec.tags || [],
      extra: rec.extra || {},
    };
    if (chainVersion != null && chainVersion >= 3) {
      obj.operator_id = rec.operator_id == null ? null : rec.operator_id;
      obj.deployer_id = rec.deployer_id == null ? null : rec.deployer_id;
      obj.system_id = rec.system_id == null ? null : rec.system_id;
    }
    return canon(obj);
  }

  async function decodeAndVerifyFromHash(fragment) {
    if (!fragment || (!fragment.startsWith('v=') && !fragment.startsWith('#v='))) {
      return { ok: false, reason: 'not a verify URL (expected #v=...)' };
    }
    const enc = fragment.replace(/^#?v=/, '');
    let payload;
    try {
      const json = b64urlDecodeText(enc);
      payload = JSON.parse(json);
    } catch (e) {
      return { ok: false, reason: 'failed to decode payload: ' + e.message };
    }
    if (!payload || payload.v !== 1) {
      return { ok: false, reason: 'unsupported format version: ' + (payload && payload.v) };
    }
    if (!payload.receipt || !payload.public_key_pem) {
      return { ok: false, reason: 'payload is missing receipt or public_key_pem' };
    }
    const rec = payload.receipt;
    const derivedCanon = canonicalReceiptPayload(rec);
    if (rec.body_canon && rec.body_canon !== derivedCanon) {
      return {
        ok: false,
        reason: 'body_canon does not match the canonical form derived from the receipt fields',
        payload, canon: derivedCanon
      };
    }
    let pubKey;
    try {
      pubKey = await importEd25519FromPem(payload.public_key_pem);
    } catch (e) {
      return { ok: false, reason: 'failed to import public key: ' + e.message, payload, canon: derivedCanon };
    }
    const sigBytes = b64DecodeBytes(rec.signature);
    const verified = await crypto.subtle.verify(
      'Ed25519', pubKey, sigBytes, enc.encode(derivedCanon)
    );
    if (!verified) {
      return { ok: false, reason: 'Ed25519 signature verification failed', payload, canon: derivedCanon };
    }
    return { ok: true, payload, canon: derivedCanon };
  }

  function renderSharedReceipt(result) {
    // Hide the normal demo; show a single-receipt verify panel.
    const demo = $('#demo');
    if (demo) demo.style.display = 'none';
    const live = $('#live');
    if (live) live.style.display = 'none';

    let panel = $('#sharedVerify');
    if (!panel) {
      panel = document.createElement('section');
      panel.id = 'sharedVerify';
      panel.className = 'section';
      panel.style.maxWidth = '780px';
      panel.style.margin = '6rem auto';
      panel.style.padding = '0 1.5rem';
      document.body.appendChild(panel);
    }

    if (!result.ok) {
      panel.innerHTML = `
        <div class="card" style="border-color: rgba(239,68,68,0.5); background: rgba(239,68,68,0.05);">
          <h2 style="margin-top:0; color: #ef4444;">✗ Verification failed</h2>
          <p style="color: var(--fg-1); font-size: 15px; line-height: 1.5;">
            ${escapeHtml(result.reason || 'unknown error')}
          </p>
          <p style="color: var(--fg-2); font-size: 13px; margin-top: 1rem;">
            The receipt data is in the URL hash, so this verification ran entirely
            in your browser. No data was sent to any server.
          </p>
        </div>
      `;
      return;
    }

    const rec = result.payload.receipt;
    const ok = result.ok;
    const card = `
      <div class="card" style="border-color: rgba(34,197,94,0.5); background: rgba(34,197,94,0.05);">
        <h2 style="margin-top:0; color: #22c55e;">✓ Verified in your browser</h2>
        <p style="color: var(--fg-1); font-size: 14px; line-height: 1.5;">
          This receipt was signed by the Ed25519 key in the URL. The signature
          matched the canonical form (sorted-keys JSON, no whitespace) of the
          receipt fields. No data was sent to any server — the verification
          ran entirely client-side.
        </p>
      </div>

      <div class="card" style="margin-top: 1rem;">
        <h3 style="margin-top:0; color: var(--fg-0);">Receipt</h3>
        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0; width: 30%;">ID</td>
              <td style="font-family: var(--font-mono);">#${escapeHtml(String(rec.id))}</td></tr>
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0;">Timestamp</td>
              <td style="font-family: var(--font-mono);">${escapeHtml(rec.timestamp)}</td></tr>
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0;">Model</td>
              <td style="font-family: var(--font-mono);">${escapeHtml(rec.model)}</td></tr>
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0;">Signing key</td>
              <td style="font-family: var(--font-mono);">${escapeHtml(rec.key_id)}</td></tr>
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0;">Payload SHA-256</td>
              <td style="font-family: var(--font-mono); word-break: break-all; font-size: 12px;">${escapeHtml(rec.payload_sha256)}</td></tr>
          <tr><td style="color: var(--fg-2); padding: 0.4rem 0;">Parent</td>
              <td style="font-family: var(--font-mono);">${rec.parent_id == null ? '— (genesis)' : '#' + escapeHtml(String(rec.parent_id))}</td></tr>
        </table>
      </div>

      <div class="card" style="margin-top: 1rem;">
        <h3 style="margin-top:0; color: var(--fg-0);">Prompt</h3>
        <pre style="white-space: pre-wrap; color: var(--fg-1); font-family: var(--font-mono); font-size: 13px; margin: 0;">${escapeHtml(rec.prompt)}</pre>
      </div>

      <div class="card" style="margin-top: 1rem;">
        <h3 style="margin-top:0; color: var(--fg-0);">Response</h3>
        <pre style="white-space: pre-wrap; color: var(--fg-1); font-family: var(--font-mono); font-size: 13px; margin: 0;">${escapeHtml(rec.response)}</pre>
      </div>

      <p style="color: var(--fg-2); font-size: 12px; margin-top: 1.5rem; text-align: center;">
        Issued as a verify-URL on ${escapeHtml(result.payload.issued_at)} ·
        Don't-Lie v0.3.3 ·
        <a href="${escapeHtml(result.payload.url || 'https://dontlie.pages.dev')}" style="color: var(--ok);">don't-lie</a>
      </p>
    `;
    panel.innerHTML = card;
    panel.scrollIntoView({ behavior: 'auto', block: 'start' });
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ============================================================
  // INIT
  // ============================================================
  async function init() {
    setupNav();
    setupReveal();
    setupCopy();
    animateTerminal();
    setupMagnetic();

    // If the URL hash is a verify-URL, run that flow instead of the demo
    const hash = (window.location.hash || '').replace(/^#/, '');
    if (hash.startsWith('v=')) {
      const result = await decodeAndVerifyFromHash(hash);
      renderSharedReceipt(result);
      return;
    }

    // Build the initial chain
    await buildChain(4);
    renderAll();

    // Wire up demo controls
    $('#tamperBtn').addEventListener('click', tamperOne);
    $('#regenBtn').addEventListener('click', regenerate);
    $('#exportBtn').addEventListener('click', exportBundle);

    // Live feed ticker
    setInterval(tickFeed, 1800);
    setInterval(tickClock, 1000);
    tickClock();
    // seed a few rows so the feed isn't empty on load
    for (let i = 0; i < 3; i++) tickFeed();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
