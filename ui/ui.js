let changePasswordBtn;
let confirmPasswordInput;
let emailInput;
let forgotPasswordBtn;
let loginBtn;
let logoutBtn;
let newPasswordInput;
let passwordInput;
let registerBtn;
let submit2FABtn;
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
      alert('Change Password failed');
    }
  } else {
    alert('Passwords do not match.');
  }
}

async function forgotPassword(event) {
  const {style} = event.target;
  style.cursor = 'wait';

  const email = emailInput.value;
  try {
    const res = await getJson(
      'user/forgot-password/' + encodeURIComponent(email)
    );
    alert('Check your email for a link to reset your password.');
  } catch (e) {
    console.error('forgotPassword error:', e);
    alert('Forgot Password failed');
  } finally {
    style.cursor = 'default';
  }
}

async function login() {
  const email = emailInput.value;
  const password = passwordInput.value;
  try {
    const res = await postJson('login', {email, password});
    if (res.status === '2FA') {
      // 2FA is enabled
      alert('Now authenticate with 2FA.');
    } else {
      loginBtn.disabled = true;
      logoutBtn.disabled = false;
      alert('Logged in');
    }
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
    alert('Logout failed');
  }
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
      alert('Register failed');
    }
  } else {
    alert('Passwords do not match.');
  }
}

async function submit2FA() {
  const email = emailInput.value;
  const password = passwordInput.value;
  const code = code2FAInput.value;
  try {
    await postJson('2fa/login', {code, email, password});
    loginBtn.disabled = true;
    logoutBtn.disabled = false;
    alert('Authenticated with 2FA');
  } catch (e) {
    console.error('submit2FA error:', e);
    alert('Failed to authenticated with 2FA');
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
    alert('Unregister failed');
  }
}

window.onload = () => {
  changePasswordBtn = document.getElementById('change-password-btn');
  code2FAInput = document.getElementById('code-2fa-input');
  confirmPasswordInput = document.getElementById('confirm-password');
  emailInput = document.getElementById('email');
  forgotPasswordBtn = document.getElementById('forgot-password-btn');
  loginBtn = document.getElementById('login-btn');
  logoutBtn = document.getElementById('logout-btn');
  newPasswordInput = document.getElementById('new-password');
  passwordInput = document.getElementById('password');
  registerBtn = document.getElementById('register-btn');
  submit2FABtn = document.getElementById('submit-2fa-btn');
  unregisterBtn = document.getElementById('unregister-btn');

  logoutBtn.disabled = true;

  changePasswordBtn.addEventListener('click', changePassword);
  forgotPasswordBtn.addEventListener('click', forgotPassword);
  loginBtn.addEventListener('click', login);
  logoutBtn.addEventListener('click', logout);
  registerBtn.addEventListener('click', register);
  submit2FABtn.addEventListener('click', submit2FA);
  unregisterBtn.addEventListener('click', unregister);
};
