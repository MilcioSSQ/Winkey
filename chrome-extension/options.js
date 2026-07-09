const input = document.getElementById('server-url');
const status = document.getElementById('status');

async function load() {
  const { serverUrl } = await chrome.storage.local.get('serverUrl');
  input.value = serverUrl || 'https://localhost:5000';
}

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.replace(/\/+$/, '');

  try {
    const granted = await chrome.permissions.request({ origins: [`${url}/*`] });
    if (!granted) {
      status.textContent = 'Berechtigung für diese Adresse wurde nicht erteilt.';
      status.style.color = '#EF4444';
      return;
    }
    await chrome.storage.local.set({ serverUrl: url });
    status.textContent = 'Gespeichert.';
    status.style.color = '#10B981';
  } catch (err) {
    status.textContent = `Fehler: ${err.message}`;
    status.style.color = '#EF4444';
  }
});

load();
