// Fetch config from server to get client ID
async function loadGoogleConfig() {
  try {
    const response = await fetch('/api/config');
    const config = await response.json();
    if (config.clientId) {
      document.getElementById('g_id_onload').setAttribute('data-client_id', config.clientId);
    }
  } catch (err) {
    console.error('Failed to load config:', err);
  }
}
