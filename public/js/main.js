// main.js - frontend helper functions (replace or merge with your existing frontend logic)
// Important: all fetch calls that require authentication include credentials: "include"

async function apiFetch(path, opts = {}) {
  if (!opts.headers) opts.headers = {};
  // Ensure JSON header for POST/PUT
  if (opts.body && !opts.headers["Content-Type"]) {
    opts.headers["Content-Type"] = "application/json";
  }
  opts.credentials = "include"; // send cookies
  const res = await fetch(path, opts);
  if (!res.ok) {
    const txt = await res.text();
    let body;
    try { body = JSON.parse(txt); } catch(e) { body = txt; }
    throw { status: res.status, body };
  }
  return res.json();
}

// Example usage:

// Register
async function register(username, password) {
  return apiFetch("/api/register", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

// Login
async function login(username, password) {
  return apiFetch("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

// Add contact
async function addContact(username) {
  return apiFetch("/api/add-contact", {
    method: "POST",
    body: JSON.stringify({ username }),
  });
}

// Create group
async function createGroup(name, members = []) {
  return apiFetch("/api/groups/create", {
    method: "POST",
    body: JSON.stringify({ name, members }),
  });
}

// Add member to group
async function addMemberToGroup(group_id, username) {
  return apiFetch("/api/groups/add-member", {
    method: "POST",
    body: JSON.stringify({ group_id, username }),
  });
}

// Send private message
async function sendPrivate(to, text) {
  return apiFetch("/api/private/send", {
    method: "POST",
    body: JSON.stringify({ to, text }),
  });
}

// Get my profile
async function fetchMe() {
  return apiFetch("/api/me", { method: "GET" });
}