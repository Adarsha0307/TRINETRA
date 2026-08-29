// TrustShield API client. The browser talks ONLY to the Node/Express backend.
const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
const API = `${BASE}/api`;

async function parse(res) {
  if (res.status === 204) return null;
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!res.ok) {
    const msg = (data && data.error) || `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

export async function apiGet(path) {
  return parse(await fetch(`${API}${path}`));
}

export async function apiPost(path, body) {
  return parse(await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }));
}

export async function apiPostForm(path, formData) {
  return parse(await fetch(`${API}${path}`, { method: 'POST', body: formData }));
}

export async function apiDelete(path) {
  return parse(await fetch(`${API}${path}`, { method: 'DELETE' }));
}
