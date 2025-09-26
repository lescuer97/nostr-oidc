// modules/certs.js

// Helper: find cert content in DOM by account and which
function getCertContentFromDOM(accountId, which) {
  const preId = `${which}-content-${accountId}`;
  const pre = document.getElementById(preId);
  if (pre && pre.textContent && pre.textContent.trim().length > 0) {
    return pre.textContent;
  }
  const row = document.getElementById(`${which}-row-${accountId}`);
  if (row) {
    const preInRow = row.querySelector('pre');
    if (preInRow && preInRow.textContent && preInRow.textContent.trim().length > 0) {
      return preInRow.textContent;
    }
  }
  return null;
}

// Init certificate copy functionality
export function initCertCopy() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.cert-copy-btn');
    if (!btn) return;

    const accountId = btn.getAttribute('data-account');
    const which = btn.getAttribute('data-which');
    if (!accountId || !which) return;

    try {
      let text = getCertContentFromDOM(accountId, which);
      if (!text) {
        const res = await fetch(`/cert/${accountId}/${which}`);
        if (!res.ok) {
          console.error('failed to fetch cert fragment', res.status);
          return;
        }
        const html = await res.text();
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        const pre = tmp.querySelector(`#${which}-content-${accountId}`) || tmp.querySelector('pre');
        text = pre ? pre.textContent : null;
      }

      if (!text) {
        console.error('no cert content found to copy');
        return;
      }

      await navigator.clipboard.writeText(text);
      const original = btn.innerHTML;
      btn.innerHTML = '✅';
      setTimeout(() => btn.innerHTML = original, 1500);
    } catch (err) {
      console.error('copy failed', err);
    }
  });
}
