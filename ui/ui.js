const URL_PREFIX = 'https://api.nodeauth.dev/';

let changePasswordBtn;
let confirmPasswordInput;
let emailInput;
let loginBtn;
let logoutBtn;
let newPasswordInput;
let passwordInput;
let registerBtn;
let unregisterBtn;

async function changePassword() {
  const email = emailInput.value;
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  const newPassword = newPasswordInput.value;
  if (newPassword === confirmPassword) {
    try {
      await postJson('user/password', {
        email,
        oldPassword: password,
        newPassword
      });
      alert('Password changed');
    } catch (e) {
      console.error('changePassword error:', e);
    }
  } else {
    alert('Passwords do not match.');
  }
}

async function deleteResource(path, body) {
  return fetch(URL_PREFIX + path, {
    credentials: 'include', // required to send cookies
    method: 'DELETE'
  });
}

async function getJson(path) {
  return fetch(URL_PREFIX + path, {
    credentials: 'include' // required to send cookies
  });
}

async function login() {
  const email = emailInput.value;
  const password = passwordInput.value;
  try {
    const res = await postJson('login', {email, password});
    loginBtn.disabled = true;
    logoutBtn.disabled = false;
    alert('Logged in');
  } catch (e) {
    console.error('login error:', e);
    alert('Login failed');
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

async function postJson(path, body) {
  const res = await fetch(URL_PREFIX + path, {
    method: 'POST',
    body: JSON.stringify(body),
    credentials: 'include', // required to send cookies
    headers: {'Content-Type': 'application/json'}
  });
  const contentType = res.headers.get('Content-Type');
  const isJson = contentType && contentType.startsWith('application/json');
  console.log('ui.js postJson: isJson =', isJson);
  const result = await (isJson ? res.json() : res.text());
  console.log('ui.js postJson: result =', result);
  if (res.ok) return result;
  throw new Error(result);
}

async function register() {
  const email = emailInput.value;
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  if (confirmPassword === password) {
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
  } else {
    alert('Passwords do not match.');
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
  changePasswordBtn = document.getElementById('change-password-btn');
  confirmPasswordInput = document.getElementById('confirm-password');
  emailInput = document.getElementById('email');
  loginBtn = document.getElementById('login-btn');
  logoutBtn = document.getElementById('logout-btn');
  newPasswordInput = document.getElementById('new-password');
  passwordInput = document.getElementById('password');
  registerBtn = document.getElementById('register-btn');
  unregisterBtn = document.getElementById('unregister-btn');

  logoutBtn.disabled = true;

  changePasswordBtn.addEventListener('click', changePassword);
  loginBtn.addEventListener('click', login);
  logoutBtn.addEventListener('click', logout);
  registerBtn.addEventListener('click', register);
  unregisterBtn.addEventListener('click', unregister);
};
