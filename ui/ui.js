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
    return 'Password changed';
  } catch (e) {
    console.error('changePassword error:', e);
    throw new Error('Change Password failed');
  }
}

async function forgotPassword(event) {
  const email = getValue('forgot-password-email');
  try {
    const res = await getJson(
      'user/forgot-password/' + encodeURIComponent(email)
    );
    return 'Check your email for a link to reset your password.';
  } catch (e) {
    console.error('forgotPassword error:', e);
    throw new Error('Forgot Password failed');
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
      return 'Now authenticate with 2FA.';
    } else {
      setLoggedIn(true);
    }
  } catch (e) {
    console.error('login error:', e);
    throw new Error('Login failed');
  }
}

async function login2FA() {
  const email = getValue('login-email');
  const password = getValue('login-password');
  const code = getValue('login-2fa-code');
  try {
    await postJson('2fa/login', {code, email, password});
    setLoggedIn(true);
    return 'Authenticated with 2FA';
  } catch (e) {
    console.error('submit2FA error:', e);
    throw new Error('Failed to authenticated with 2FA');
  }
}

async function logout() {
  try {
    await getJson('logout', {});
    setLoggedIn(false);
  } catch (e) {
    console.error('logout error:', e);
    throw new Error('Logout failed');
  }
}

function onSubmit(formId, handler) {
  document.getElementById(formId).addEventListener('submit', async event => {
    setCursor(event.target, 'wait');
    event.preventDefault();
    try {
      const message = await handler(event);
      if (message) alert(message);
    } catch (e) {
      alert(e.message);
    } finally {
      setCursor(event.target, 'default');
    }
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
      return 'Check your email for a link to verify your account.';
    } catch (e) {
      console.error('register error:', e);
      throw new Error('Register failed');
    }
  } else {
    throw new Error('Passwords do not match.');
  }
}

function setCursor(form, cursor) {
  document.body.style.cursor = cursor;
  const buttons = form.querySelectorAll('button');
  for (const button of buttons) {
    button.style.cursor = cursor;
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
  try {
    await deleteResource('user'); // deletes current user
    await logout(); // deletes current session
    return 'Unregistered user';
  } catch (e) {
    console.error('unregister error:', e);
    throw new Error('Unregister failed');
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
