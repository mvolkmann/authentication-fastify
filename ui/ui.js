async function changePassword() {
  const email = getValue('change-password-email');
  const oldPassword = getValue('change-password-old-password');
  const newPassword = getValue('change-password-new-password');
  try {
    await postJson('user/password', {
      email,
      oldPassword,
      newPassword
    });
    alert('Password changed');
  } catch (e) {
    console.error('changePassword error:', e);
    alert('Change Password failed');
  }
}

async function forgotPassword(event) {
  const {style} = event.target;
  style.cursor = 'wait';

  const email = getValue('forgot-password-email');
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

function getValue(id) {
  return document.getElementById(id).value;
}

async function login() {
  const email = getValue('login-email');
  const password = getValue('login-password');
  try {
    const res = await postJson('login', {email, password});
    if (res.status === '2FA') {
      // 2FA is enabled
      alert('Now authenticate with 2FA.');
    } else {
      setLoggedIn(true);
      alert('Logged in');
    }
  } catch (e) {
    console.error('login error:', e);
    alert('Login failed');
  }
}

async function login2FA() {
  const email = getValue('login-email');
  const password = getValue('login-password');
  const code = getValue('login-2fa-code');
  try {
    await postJson('2fa/login', {code, email, password});
    setLoggedIn(true);
    alert('Authenticated with 2FA');
  } catch (e) {
    console.error('submit2FA error:', e);
    alert('Failed to authenticated with 2FA');
  }
}

async function logout() {
  try {
    await getJson('logout', {});
    setLoggedIn(false);
    alert('Logged out');
  } catch (e) {
    console.error('logout error:', e);
    alert('Logout failed');
  }
}

function onSubmit(formId, handler) {
  document.getElementById(formId).addEventListener('submit', event => {
    event.preventDefault();
    handler(event);
  });
}

async function register() {
  const email = getValue('register-email');
  const password = getValue('register-password');
  const confirmPassword = getValue('register-confirm-password');
  if (confirmPassword === password) {
    try {
      const {userId} = await postJson('user', {email, password});
      setLoggedIn(true);
      alert('Check your email for a link to verify your account.');
    } catch (e) {
      console.error('register error:', e);
      alert('Register failed');
    }
  } else {
    alert('Passwords do not match.');
  }
}

function setLoggedIn(loggedIn) {
  const changePassword = document.querySelector('form#change-password');
  const enable2FA = document.querySelector('form#enable-2fa');
  const forgotPassword = document.querySelector('form#forgot-password');
  const login = document.querySelector('form#login');
  const login2FA = document.querySelector('form#login-2fa');
  const logout = document.querySelector('form#logout');
  const unregister = document.querySelector('form#unregister');

  const hide = element => (element.style.display = 'none');
  const show = element => (element.style.display = 'block');

  if (loggedIn) {
    hide(forgotPassword);
    hide(login);
    hide(login2FA);
    show(changePassword);
    show(enable2FA);
    show(logout);
    show(unregister);
  } else {
    hide(changePassword);
    hide(enable2FA);
    hide(logout);
    hide(unregister);
    show(forgotPassword);
    show(login);
    show(login2FA);
  }
}

async function unregister() {
  const email = getValue('unregister-email');
  const password = getValue('unregister-password');
  try {
    //TODO: Call a service that verifies the password before deleting the account.
    await deleteResource('user/' + encodeURIComponent(email));
    alert('Unregistered user');
  } catch (e) {
    console.error('unregister error:', e);
    alert('Unregister failed');
  }
}

window.onload = () => {
  onSubmit('change-password', changePassword);
  onSubmit('login', login);
  onSubmit('logout', logout);
  onSubmit('register', register);
  onSubmit('unregister', unregister);
  onSubmit('forgot-password', forgotPassword);
  onSubmit('login-2fa', login2FA);

  setLoggedIn(false);
};
