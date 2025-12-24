const api = path => `/api${path}`;

let authToken = localStorage.getItem('authToken');
let currentUser = null;

function $id(id) {
  return document.getElementById(id);
}

function getAuthHeaders() {
  return {
    'Authorization': `Bearer ${authToken}`
  };
}

// ==================== SCREEN MANAGEMENT ====================

function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
  $id(screenId).classList.remove('hidden');
}

function showLogin() {
  showScreen('loginScreen');
  $id('loginForm').reset();
  $id('loginError').classList.add('hidden');
}

function showContacts() {
  showScreen('contactScreen');
  updateContactNavbar();
  load();
}

function showAdmin() {
  // STRICT ACCESS CONTROL: Verify admin role
  if (!currentUser || currentUser.role !== 'admin') {
    showAccessDenied();
    return;
  }
  
  showScreen('adminScreen');
  updateAdminNavbar();
  loadUsers();
}

function showAccessDenied() {
  $id('accessDeniedModal').classList.remove('hidden');
}

function hideAccessDenied() {
  $id('accessDeniedModal').classList.add('hidden');
}

// ==================== AUTHENTICATION ====================

async function verifyAuth() {
  if (!authToken) return false;
  
  try {
    const res = await fetch(api('/auth/verify'), {
      headers: getAuthHeaders()
    });
    
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      return true;
    }
    
    logout();
    return false;
  } catch (err) {
    console.error('Auth verification error:', err);
    logout();
    return false;
  }
}

function logout() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem('authToken');
  showLogin();
}

function updateContactNavbar() {
  if (currentUser) {
    $id('navUsername').textContent = currentUser.username;
    $id('navRole').textContent = currentUser.role.toUpperCase();
    $id('navRole').className = `role-badge ${currentUser.role}`;
    
    // Show admin button ONLY for admins
    if (currentUser.role === 'admin') {
      $id('navAdminBtn').classList.remove('hidden');
    } else {
      $id('navAdminBtn').classList.add('hidden');
    }
  }
}

function updateAdminNavbar() {
  if (currentUser) {
    $id('adminUsername').textContent = currentUser.username;
  }
}

// ==================== MESSAGES ====================

function showMessage(msg, type = 'info', targetId = 'contactMessage') {
  const msgEl = $id(targetId);
  msgEl.textContent = msg;
  msgEl.className = `message ${type}`;
  msgEl.classList.remove('hidden');
  
  setTimeout(() => {
    msgEl.classList.add('hidden');
  }, 4000);
}

// ==================== CONTACTS ====================

async function fetchContacts(q = '') {
  try {
    const url = api(`/contacts${q ? `?search=${encodeURIComponent(q)}` : ''}`);
    const res = await fetch(url, {
      headers: getAuthHeaders()
    });
    
    if (res.status === 401 || res.status === 403) {
      logout();
      return [];
    }
    
    if (!res.ok) {
      throw new Error('Failed to fetch contacts');
    }
    
    return res.json();
  } catch (err) {
    console.error('Fetch contacts error:', err);
    showMessage('Failed to load contacts', 'error');
    return [];
  }
}

function render(contacts) {
  const list = $id('contacts');
  const emptyState = $id('emptyState');
  
  list.innerHTML = '';
  
  if (contacts.length === 0) {
    list.classList.add('hidden');
    emptyState.classList.remove('hidden');
    return;
  }
  
  list.classList.remove('hidden');
  emptyState.classList.add('hidden');
  
  contacts.forEach(c => {
    const li = document.createElement('li');
    li.className = 'contact-item';
    
    const avatar = document.createElement('div');
    avatar.className = 'contact-avatar';
    if (c.icon) {
      const img = document.createElement('img');
      img.src = c.icon;
      img.alt = c.name;
      avatar.appendChild(img);
    } else {
      avatar.innerHTML = `<div class="avatar-placeholder">${getInitials(c.name)}</div>`;
    }
    
    const info = document.createElement('div');
    info.className = 'contact-info';
    
    const name = document.createElement('div');
    name.className = 'contact-name';
    name.textContent = escapeHtml(c.name);
    
    const details = document.createElement('div');
    details.className = 'contact-details';
    
    if (c.email) {
      const email = document.createElement('span');
      email.className = 'contact-email';
      email.innerHTML = `📧 ${escapeHtml(c.email)}`;
      details.appendChild(email);
    }
    
    if (c.phone) {
      const phone = document.createElement('span');
      phone.className = 'contact-phone';
      phone.innerHTML = `📱 ${escapeHtml(c.phone)}`;
      details.appendChild(phone);
    }
    
    info.appendChild(name);
    info.appendChild(details);
    
    if (c.notes) {
      const notes = document.createElement('div');
      notes.className = 'contact-notes';
      notes.textContent = escapeHtml(c.notes);
      info.appendChild(notes);
    }
    
    const actions = document.createElement('div');
    actions.className = 'contact-actions';
    
    const editBtn = document.createElement('button');
    editBtn.className = 'btn-icon-text btn-edit';
    editBtn.innerHTML = '<span>✏️</span> Edit';
    editBtn.onclick = () => openForm(c);
    
    const delBtn = document.createElement('button');
    delBtn.className = 'btn-icon-text btn-delete';
    delBtn.innerHTML = '<span>🗑️</span> Delete';
    delBtn.onclick = () => deleteContact(c);
    
    actions.append(editBtn, delBtn);
    li.append(avatar, info, actions);
    list.appendChild(li);
  });
}

function getInitials(name) {
  return name
    .split(' ')
    .map(n => n[0])
    .join('')
    .toUpperCase()
    .substring(0, 2);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function load(q = '') {
  const contacts = await fetchContacts(q);
  render(contacts);
}

function openForm(contact) {
  $id('formWrap').classList.remove('hidden');
  $id('formTitle').textContent = contact ? 'Edit Contact' : 'New Contact';
  $id('contactId').value = contact?.id || '';
  $id('name').value = contact?.name || '';
  $id('email').value = contact?.email || '';
  $id('phone').value = contact?.phone || '';
  $id('notes').value = contact?.notes || '';
  $id('icon').value = '';
  
  // Scroll to form
  $id('formWrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeForm() {
  $id('formWrap').classList.add('hidden');
  $id('contactForm').reset();
  $id('contactId').value = '';
}

async function deleteContact(contact) {
  if (!confirm(`Are you sure you want to delete "${contact.name}"?\n\nThis action cannot be undone.`)) {
    return;
  }
  
  try {
    const res = await fetch(api(`/contacts/${contact.id}`), {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    
    if (res.ok) {
      load();
      showMessage('Contact deleted successfully', 'success');
    } else {
      const data = await res.json();
      showMessage(data.error || 'Failed to delete contact', 'error');
    }
  } catch (err) {
    showMessage('Network error occurred', 'error');
  }
}

// ==================== ADMIN PANEL ====================

async function loadUsers() {
  try {
    const res = await fetch(api('/users'), {
      headers: getAuthHeaders()
    });
    
    if (res.status === 403) {
      showAccessDenied();
      setTimeout(() => showContacts(), 2000);
      return;
    }
    
    if (!res.ok) {
      throw new Error('Failed to load users');
    }
    
    const users = await res.json();
    renderUsersTable(users);
    updateStatistics(users);
  } catch (err) {
    console.error('Load users error:', err);
    showMessage('Failed to load users', 'error', 'adminMessage');
  }
}

function renderUsersTable(users) {
  const tbody = $id('usersTableBody');
  tbody.innerHTML = '';
  
  if (users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="text-center empty-cell">No users found</td>
      </tr>
    `;
    return;
  }
  
  users.forEach(u => {
    const tr = document.createElement('tr');
    
    const isCurrentUser = u.id === currentUser.id;
    
    tr.innerHTML = `
      <td>
        <div class="user-cell">
          <span class="user-avatar">${u.username.charAt(0).toUpperCase()}</span>
          <span class="user-name">${escapeHtml(u.username)}</span>
          ${isCurrentUser ? '<span class="badge-you">You</span>' : ''}
        </div>
      </td>
      <td>
        <span class="role-badge ${u.role}">${u.role.toUpperCase()}</span>
      </td>
      <td>${formatDate(u.created_at)}</td>
      <td class="text-center">
        ${isCurrentUser ? 
          '<span class="text-muted">Current user</span>' :
          `<button class="btn-delete-user" onclick="deleteUser('${u.id}', '${escapeHtml(u.username)}')">
            <span>🗑️</span> Delete
          </button>`
        }
      </td>
    `;
    
    tbody.appendChild(tr);
  });
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric' 
  });
}

function updateStatistics(users) {
  const totalUsers = users.length;
  const regularUsers = users.filter(u => u.role === 'user').length;
  const admins = users.filter(u => u.role === 'admin').length;
  
  $id('statTotalUsers').textContent = totalUsers;
  $id('statRegularUsers').textContent = regularUsers;
  $id('statAdmins').textContent = admins;
}

async function deleteUser(userId, username) {
  if (!confirm(`Delete user "${username}"?\n\nAll data associated with this user will be permanently removed.`)) {
    return;
  }
  
  try {
    const res = await fetch(api(`/users/${userId}`), {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    
    if (res.ok) {
      showMessage('User deleted successfully', 'success', 'adminMessage');
      loadUsers();
    } else {
      const data = await res.json();
      showMessage(data.error || 'Failed to delete user', 'error', 'adminMessage');
    }
  } catch (err) {
    showMessage('Network error occurred', 'error', 'adminMessage');
  }
}

// ==================== EVENT LISTENERS ====================

document.addEventListener('DOMContentLoaded', async () => {
  // Check authentication on load
  const isAuth = await verifyAuth();
  
  if (isAuth) {
    showContacts();
  } else {
    showLogin();
  }
  
  // Login form
  $id('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = $id('loginUsername').value.trim();
    const password = $id('loginPassword').value;
    
    const loginError = $id('loginError');
    loginError.classList.add('hidden');
    
    try {
      const res = await fetch(api('/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      if (res.ok) {
        const data = await res.json();
        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        
        showContacts();
      } else {
        const data = await res.json();
        loginError.textContent = data.error || 'Invalid username or password';
        loginError.classList.remove('hidden');
      }
    } catch (err) {
      loginError.textContent = 'Network error. Please try again.';
      loginError.classList.remove('hidden');
    }
  });
  
  // Logout buttons
  $id('navLogoutBtn').addEventListener('click', logout);
  $id('adminLogoutBtn').addEventListener('click', logout);
  
  // Navigation
  $id('navAdminBtn').addEventListener('click', () => {
    // Double-check admin access
    if (currentUser && currentUser.role === 'admin') {
      showAdmin();
    } else {
      showAccessDenied();
    }
  });
  
  $id('backToContactsBtn').addEventListener('click', showContacts);
  
  // Contact actions
  $id('newBtn').addEventListener('click', () => openForm(null));
  $id('emptyAddBtn').addEventListener('click', () => openForm(null));
  $id('closeFormBtn').addEventListener('click', closeForm);
  $id('cancelFormBtn').addEventListener('click', closeForm);
  
  // Search
  $id('search').addEventListener('input', (e) => {
    const query = e.target.value.trim();
    load(query);
  });
  
  // Contact form submission
  $id('contactForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const id = $id('contactId').value;
    const fd = new FormData();
    fd.append('name', $id('name').value.trim());
    fd.append('email', $id('email').value.trim());
    fd.append('phone', $id('phone').value.trim());
    fd.append('notes', $id('notes').value.trim());
    
    const file = $id('icon').files[0];
    if (file) {
      if (file.size > 200000) {
        showMessage('Image size must be less than 200KB', 'error');
        return;
      }
      fd.append('icon', file);
    }
    
    try {
      const res = await fetch(
        api(id ? `/contacts/${id}` : '/contacts'),
        {
          method: id ? 'PUT' : 'POST',
          headers: getAuthHeaders(),
          body: fd
        }
      );
      
      if (res.ok) {
        closeForm();
        load();
        showMessage(
          id ? 'Contact updated successfully' : 'Contact created successfully',
          'success'
        );
      } else {
        const data = await res.json();
        showMessage(data.error || 'Operation failed', 'error');
      }
    } catch (err) {
      showMessage('Network error occurred', 'error');
    }
  });
  
  // Admin panel actions
  $id('refreshUsersBtn').addEventListener('click', loadUsers);
  
  // Register form
  $id('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = $id('regUsername').value.trim();
    const password = $id('regPassword').value;
    const role = $id('regRole').value;
    
    if (!role) {
      showMessage('Please select a role', 'error', 'adminMessage');
      return;
    }
    
    try {
      const res = await fetch(api('/auth/register'), {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, role })
      });
      
      if (res.ok) {
        showMessage('User created successfully', 'success', 'adminMessage');
        $id('registerForm').reset();
        loadUsers();
      } else {
        const data = await res.json();
        showMessage(data.error || 'Failed to create user', 'error', 'adminMessage');
      }
    } catch (err) {
      showMessage('Network error occurred', 'error', 'adminMessage');
    }
  });
  
  // Access denied modal
  $id('closeAccessDeniedBtn').addEventListener('click', hideAccessDenied);
  
  // Prevent admin access via URL manipulation
  window.addEventListener('popstate', async () => {
    const isAuth = await verifyAuth();
    if (!isAuth) {
      showLogin();
    }
  });
});