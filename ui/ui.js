const URL_PREFIX = 'https://api.nodeauth.dev/';
let emailInput;
let loginBtn;
let logoutBtn;
let passwordInput;
let registerBtn;
let unregisterBtn;

async function deleteResource(path, body) {
  try {
    return fetch(URL_PREFIX + path, {
      credentials: 'include', // required to send cookies
      method: 'DELETE'
    });
  } catch (e) {
    console.error('deleteResource error:', e);
  }
}

async function getJson(path) {
  try {
    return fetch(URL_PREFIX + path, {
      credentials: 'include' // required to send cookies
    });
  } catch (e) {
    console.error('getJson error:', e);
  }
}

async function postJson(path, body) {
  try {
    const res = await fetch(URL_PREFIX + path, {
      method: 'POST',
      body: JSON.stringify(body),
      credentials: 'include', // required to send cookies
      headers: {'Content-Type': 'application/json'}
    });
    const contentType = res.headers.get('Content-Type');
    const isJson = contentType && contentType.startsWith('application/json');
    const result = await (isJson ? res.json() : res.text());
    if (res.ok) return result;
    throw new Error(result);
  } catch (e) {
    console.error('postJson error:', e);
  }
}

async function login() {
  const email = emailInput.value;
  const password = passwordInput.value;
  try {
    await postJson('login', {email, password});
    loginBtn.disabled = true;
    logoutBtn.disabled = false;
    alert('Logged in');
  } catch (e) {
    console.error('login error:', e);
  }
}

async function logout() {
  try {
    await getJson('logout', {});
    loginBtn.disabled = false;
    logoutBtn.disabled = true;
    alert('Logged out');
  } catch (e) {
    console.error('logout error:', e);
  }
}

async function register() {
  const email = emailInput.value;
  const password = passwordInput.value;
  try {
    const {userId} = await postJson('user', {email, password});
    registerBtn.disabled = true;
    unregisterBtn.disabled = false;
    loginBtn.disabled = true;
    logoutBtn.disabled = false;
    alert('Check your email for a link to verify your account.');
  } catch (e) {
    console.error('register error:', e);
  }
}

async function unregister() {
  const email = emailInput.value;
  try {
    await deleteResource('user/' + encodeURIComponent(email));
    registerBtn.disabled = false;
    unregisterBtn.disabled = true;
    alert('Unregistered user');
  } catch (e) {
    console.error('unregister error:', e);
  }
}

window.onload = () => {
  emailInput = document.getElementById('email');
  passwordInput = document.getElementById('password');
  loginBtn = document.getElementById('login-btn');
  logoutBtn = document.getElementById('logout-btn');
  registerBtn = document.getElementById('register-btn');
  unregisterBtn = document.getElementById('unregister-btn');

  logoutBtn.disabled = true;

  loginBtn.addEventListener('click', login);
  logoutBtn.addEventListener('click', logout);
  registerBtn.addEventListener('click', register);
  unregisterBtn.addEventListener('click', unregister);
};
