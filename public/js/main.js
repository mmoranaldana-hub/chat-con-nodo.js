// public/js/main.js - versión corregida (reemplazar completa)
const socket = io();
let me = null;
let current = { type: 'global' };

// helper API (siempre añade /api delante)
async function api(path, method='GET', body){
  const opts = { method, headers: {}, credentials: 'include' };
  if(body){ opts.headers['Content-Type']='application/json'; opts.body = JSON.stringify(body); }
  try {
    const res = await fetch('/api' + path, opts);
    const txt = await res.text();
    try { return JSON.parse(txt); } catch(e) { return txt; }
  } catch(e){
    console.error('API fetch error', e);
    return null;
  }
}

/* ------------------ UI + Auth ------------------ */
document.getElementById('show-register').addEventListener('click', ()=>{ document.getElementById('login-form').style.display='none'; document.getElementById('register-form').style.display='block'; });
document.getElementById('show-login').addEventListener('click', ()=>{ document.getElementById('login-form').style.display='block'; document.getElementById('register-form').style.display='none'; });

document.getElementById('login-btn').addEventListener('click', async ()=>{
  const u = document.getElementById('login-username').value.trim();
  const p = document.getElementById('login-password').value.trim();
  if(!u||!p){ document.getElementById('auth-msg').textContent='Completa usuario y contraseña'; return; }
  const r = await api('/login','POST',{ username:u, password:p });
  if(!r){ document.getElementById('auth-msg').textContent='Error servidor'; return; }
  if(r.error){ document.getElementById('auth-msg').textContent = r.error; return; }
  await initAfterAuth();
});

document.getElementById('reg-btn').addEventListener('click', async ()=>{
  const u = document.getElementById('reg-username').value.trim();
  const p = document.getElementById('reg-password').value.trim();
  if(!u||!p){ document.getElementById('auth-msg').textContent='Completa usuario y contraseña'; return; }
  const r = await api('/register','POST',{ username:u, password:p });
  if(!r){ document.getElementById('auth-msg').textContent='Error servidor'; return; }
  if(r.error){ document.getElementById('auth-msg').textContent = r.error; return; }
  await initAfterAuth();
});

async function checkSession(){
  const r = await api('/me', 'GET');
  if(r && r.user) await initAfterAuth();
  else { document.getElementById('auth').style.display='block'; document.getElementById('app').style.display='none'; }
}

async function initAfterAuth(){
  const r = await api('/me', 'GET');
  if(!r || !r.user){ document.getElementById('auth').style.display='block'; document.getElementById('app').style.display='none'; return; }
  me = r.user;
  document.getElementById('me-name').textContent = me.username;
  document.getElementById('me-presence').textContent = 'En línea';
  if(me.avatar){ document.getElementById('me-avatar-img').src = me.avatar; document.getElementById('me-avatar-img').style.display='block'; document.getElementById('me-avatar-initial').style.display='none'; }
  if(me.description) document.getElementById('me-desc').textContent = me.description;
  document.getElementById('auth').style.display='none'; document.getElementById('app').style.display='flex';
  socket.emit('online', me.id);
  bindUI();
  await refreshAll();
  setInterval(refreshAll, 5000);
}

/* ------------------ UI bindings ------------------ */
function bindUI(){
  document.getElementById('add-contact-btn').onclick = async ()=>{
    const username = document.getElementById('add-contact-name').value.trim(); if(!username) return alert('Escribe un usuario');
    const r = await api('/add-contact','POST',{ username });
    if(!r){ return alert('Error servidor'); }
    if(r.error) return alert(r.error);
    document.getElementById('add-contact-name').value='';
    alert('Contacto agregado');
    await loadContacts();
  };

  document.getElementById('create-group-btn').onclick = async ()=>{
    const name = document.getElementById('new-group-name').value.trim(); if(!name) return alert('Nombre requerido');
    // ruta correcta: /api/groups/create (la función api añade /api)
    const r = await api('/groups/create','POST',{ name, members: [] });
    if(r && r.error) return alert(r.error);
    document.getElementById('new-group-name').value='';
    await loadGroups();
  };

  document.getElementById('send-btn').onclick = sendMessage;
  document.getElementById('message-input').addEventListener('keydown', (e)=>{ if(e.key==='Enter') sendMessage(); });

  document.getElementById('logout-btn').onclick = async ()=>{ await api('/logout','POST'); location.reload(); };

  document.getElementById('change-avatar').onclick = ()=>{ document.getElementById('avatar-file').click(); };
  document.getElementById('avatar-file').addEventListener('change', async (e)=>{
    const f = e.target.files[0]; if(!f) return; const reader = new FileReader(); reader.onload = async ()=>{
      const dataUrl = reader.result; const r = await api('/me/profile','POST',{ avatar: dataUrl }); if(r && r.ok){ document.getElementById('me-avatar-img').src = dataUrl; document.getElementById('me-avatar-img').style.display='block'; document.getElementById('me-avatar-initial').style.display='none'; }
    }; reader.readAsDataURL(f);
  });

  document.getElementById('edit-desc').onclick = async ()=>{
    const desc = prompt('Escribe una descripción (visible en tu perfil):', document.getElementById('me-desc').textContent || '');
    if(desc!==null){ const r = await api('/me/profile','POST',{ description: desc }); if(r && r.ok){ document.getElementById('me-desc').textContent = desc; } }
  };

  document.getElementById('toggle-dark').onclick = ()=>{ document.body.classList.toggle('dark'); };

  // emoji picker (same as before)
}

/* ------------------ Refresh / Load ------------------ */
async function refreshAll(){ await loadContacts(); await loadGroups(); await updateUserCount(); }

async function loadContacts(){
  const cs = await api('/contacts');
  const list = document.getElementById('contacts-list');
  list.innerHTML='';
  // Global entry
  const g = document.createElement('div'); g.className='item';
  g.innerHTML = `<div style="width:40px"><div class="logo">G</div></div><div class="meta"><div class="title">Global</div><div class="small">Chat público</div></div>`;
  g.onclick = ()=> openGlobal(); list.appendChild(g);

  const grpLabel = document.createElement('div'); grpLabel.className='small'; grpLabel.style.margin='8px 8px 4px 8px'; grpLabel.textContent='Grupos'; list.appendChild(grpLabel);
  const contLabel = document.createElement('div'); contLabel.className='small'; contLabel.style.margin='8px 8px 4px 8px'; contLabel.textContent='Contactos'; list.appendChild(contLabel);

  if(Array.isArray(cs)){
    cs.forEach(c=>{
      const el = document.createElement('div'); el.className='item';
      el.innerHTML = `<div style="width:44px"><div class="me-avatar">${c.avatar?'<img src="'+c.avatar+'"/>':(c.username[0].toUpperCase())}</div></div><div class="meta"><div class="title">${c.username} ${c.online?'<span style="color:#34d859">●</span>':''}</div><div class="small">${c.online? 'En línea' : 'Desconectado'}</div></div>`;
      el.onclick = ()=> openPrivate(c.id,c.username);
      list.appendChild(el);
    });
  }
}

async function loadGroups() {
  const data = await api('/groups');
  const groups = data.groups || [];

  // El contenedor general
  const list = document.getElementById('contacts-list');

  // Elimina todos los items anteriores
  const oldGroups = list.querySelectorAll('.group-item');
  oldGroups.forEach(g => g.remove());

  // Buscar el punto donde insertar antes de "Contactos"
  const contactsHeader = Array.from(list.children).find(el => el.textContent === "Contactos");

  groups.forEach(gr => {
    const el = document.createElement("div");
    el.className = "item group-item";

    el.innerHTML = `
      <div style="width:44px">
        <div class="me-avatar">#</div>
      </div>
      <div class="meta">
        <div class="title">${gr.name}</div>
        <div class="small">${gr.members.length} miembros</div>
      </div>
    `;

    el.onclick = () => openGroup(gr.id, gr.name);

    if (contactsHeader)
      list.insertBefore(el, contactsHeader);
    else
      list.appendChild(el);
  });
}


/* ------------------ Open chat functions ------------------ */
async function openGlobal(){
  current = { type:'global' };
  document.getElementById('chat-name').textContent='Global';
  document.getElementById('chat-sub').textContent='Chat público';
  document.getElementById('messages').innerHTML='';
  const msgs = await api('/messages');
  if(Array.isArray(msgs)) msgs.forEach(render);
  scrollBottom();
  socket.emit('join_group',0);
}

async function openPrivate(id,name){
  current = { type:'private', withId:id };
  document.getElementById('chat-name').textContent = name;
  document.getElementById('chat-sub').textContent = 'Chat privado';
  document.getElementById('messages').innerHTML='';
  const msgs = await api('/private/'+id);
  if(Array.isArray(msgs)) msgs.forEach(render);
  scrollBottom();
  // join room so server can send pm events
  socket.emit('join_private',{ me: me.id, other: id });
}

async function openGroup(id,name){
  current = { type:'group', id, name };
  document.getElementById('chat-name').textContent = name;
  document.getElementById('chat-sub').textContent='Grupo';
  document.getElementById('messages').innerHTML='';
  const msgs = await api('/groups/messages/'+id);
  if(Array.isArray(msgs)) msgs.forEach(render);
  scrollBottom();
  socket.emit('join_group', id);
}

/* ------------------ Render / send message ------------------ */
function render(m){
  // normalize fields
  if(m.from_id !== undefined) m.from = m.from_id;
  if(m.to_id !== undefined) m.to = m.to_id;
  if(m.user_id !== undefined && !m.username && me && m.user_id === me.id) m.username = me.username;

  const box = document.getElementById('messages');
  const el = document.createElement('div');
  const isMe = me && ((m.user_id && m.user_id===me.id) || (m.from && m.from===me.id));
  el.className = 'msg ' + (isMe? 'me':'other');

  const meta = document.createElement('div'); meta.className='meta';
  const who = m.username || m.fromName || ('User '+(m.from||m.user_id||''));
  meta.textContent = who + ' • ' + (m.created_at ? new Date(m.created_at).toLocaleString() : '');
  const body = document.createElement('div'); body.textContent = m.text || '';

  el.appendChild(meta); el.appendChild(body);
  box.appendChild(el);
}

function scrollBottom(){
  const box=document.getElementById('messages');
  setTimeout(()=>{ box.scrollTop = box.scrollHeight; },50);
}

async function sendMessage(){
  const input = document.getElementById('message-input');
  const text = input.value.trim(); if(!text) return;
  input.value='';
  if(current.type==='global'){ await api('/messages','POST',{ text }); }
  else if(current.type==='private'){ await api('/private/send','POST',{ to: current.withId, text }); }
  else if(current.type==='group'){ await api('/groups/send','POST',{ group_id: current.id, text }); }
}

/* ------------------ SOCKET LISTENERS (REALTIME) ------------------ */
socket.on('message',(m)=>{
  // global chat
  if(current.type==='global'){ render(m); scrollBottom(); }
});

socket.on("private_message", (m) => {
  const sender = m.from || m.from_id;
  const target = m.to || m.to_id;

  // Mensaje pertenece al chat abierto
  if (current.type === "private" && current.withId === sender) {
    render(m);
    scrollBottom();
    return;
  }

  // O si soy el destinatario y estoy escribiendo con el otro
  if (current.type === "private" && current.withId === target) {
    render(m);
    scrollBottom();
    return;
  }

  // Si no es el chat abierto, actualizar lista (para mostrar “nuevo mensaje”)
  loadContacts();
});


socket.on('group_message',(m)=>{
  if(m.group_id === undefined && m.groupId) m.group_id = m.groupId;
  if(current.type==='group' && m.group_id===current.id){
    render(m);
    scrollBottom();
  } else {
    loadGroups();
  }
});

// when a group is created or members added, refresh
socket.on('group_created', ()=> loadGroups());
socket.on('group_member_added', ()=> loadGroups());
socket.on('presence_update', ()=>{ loadContacts(); updateUserCount(); });

/* ------------------ helpers ------------------ */
async function updateUserCount(){ const cs = await api('/contacts'); const online = (cs||[]).filter(x=>x.online).length; document.getElementById('user-count').textContent = online + ' online'; }

/* ------------------ init ------------------ */
(async ()=>{ await checkSession(); })();

//update 1 

/* === Admin & Member Management === */
async function setAdmin(group_id, user_id, makeAdmin){
  const r = await api('/groups/set-admin','POST',{ group_id, user_id, is_admin: !!makeAdmin });
  if(r && r.error) return alert(r.error);
  await loadGroups();
  if(current && current.type==='group' && current.id===group_id) openGroup(group_id, current.name);
}

async function removeMember(group_id, user_id){
  if(!confirm('Expulsar a este miembro del grupo?')) return;
  const r = await api('/groups/remove-member','POST',{ group_id, user_id });
  if(r && r.error) return alert(r.error);
  await loadGroups();
  if(current && current.type==='group' && current.id===group_id) openGroup(group_id, current.name);
}