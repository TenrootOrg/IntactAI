/**
 * Show / Hide on every password field of the page (setup.html, login.html).
 *
 * Setup asks for a 15+ character password twice and refuses a mismatch it does
 * not show -- the operator could not see which of the two was mistyped. Each
 * field gets its own toggle, so one can be checked without exposing the other.
 * The field goes back to type=password on submit, so a password manager still
 * recognises it.
 */
(function () {
  function addToggle(input) {
    if (input.dataset.pwToggle) return;
    input.dataset.pwToggle = '1';
    const wrap = document.createElement('span');
    wrap.style.cssText = 'position:relative;display:block';
    // The field's own bottom margin moves to the wrapper, so the button centres on the field.
    wrap.style.marginBottom = input.style.marginBottom || '0';
    input.style.marginBottom = '0';
    input.style.paddingRight = '64px';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement('button');
    btn.type = 'button';                              // never submits the form
    btn.className = 'pw-toggle';
    btn.textContent = 'Show';
    btn.setAttribute('aria-pressed', 'false');
    btn.setAttribute('aria-controls', input.id || '');
    btn.setAttribute('aria-label', 'Show password');
    btn.style.cssText = 'position:absolute;right:6px;top:50%;transform:translateY(-50%);' +
      'padding:4px 8px;border:none;border-radius:4px;background:transparent;' +
      'color:#9ca3af;font-size:12px;cursor:pointer';
    btn.addEventListener('click', function () {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-pressed', String(show));
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
    wrap.appendChild(btn);

    if (input.form) input.form.addEventListener('submit', function () {
      input.type = 'password';
      btn.textContent = 'Show';
      btn.setAttribute('aria-pressed', 'false');
      btn.setAttribute('aria-label', 'Show password');
    }, true);
  }
  function init() { document.querySelectorAll('input[type="password"]').forEach(addToggle); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
  window.addPasswordToggles = init;
})();
