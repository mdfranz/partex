// Fixture JS bundle for js-analysis tests
const APP_CONFIG = {
  appVersion: '2.4.1',
  commitSha: 'a1b2c3d4',
  apiKey: 'sk-fixture-secret-value-9876543210',
  placeholderKey: 'changeme',
};

export async function loadUsers() {
  const res = await fetch('/api/v1/users');
  return res.json();
}

export function renderBanner(el, html) {
  el.innerHTML = html;
}

//# sourceMappingURL=app.js.map
