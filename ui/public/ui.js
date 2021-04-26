// Currently there are no requirements on passwords.
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

function clearInput(id) {
  document.getElementById(id).value = '';
}

// The server should only honor this for admin users.
async function deleteUser() {
  const email = getValue('delete-user-email');
  try {
    await deleteResource('user/' + encodeURIComponent(email));
    return 'User deleted';
  } catch (e) {
    console.error('deleteUser error:', e);
    throw new Error(e);
  }
}

// The server should only honor this for admin users.
async function deleteUserSessions() {
  const email = getValue('delete-user-sessions-email');
  try {
    await deleteResource(`user/${encodeURIComponent(email)}/sessions`);
    return 'User Sessions deleted';
  } catch (e) {
    console.error('deleteUserSessions error:', e);
    throw new Error(e);
  }
}

async function forgotPassword() {
  const email = getValue('forgot-password-email');
  try {
    await getJson('user/forgot-password/' + encodeURIComponent(email));
    return 'Check your email for a link to reset your password.';
  } catch (e) {
    console.error('forgotPassword error:', e);
    throw new Error('Forgot Password failed');
  }
}

// Gets the value of a form element.
function getValue(id) {
  return document.getElementById(id).value;
}

// Hides all elements that match a given selector.
function hide(selector) {
  const elements = document.querySelectorAll(selector);
  for (const element of elements) {
    element.style.display = 'none';
  }
}

async function login() {
  const email = getValue('login-email');
  const password = getValue('login-password');
  try {
    const res = await postJson('login', {email, password});
    if (res.status === '2FA') {
      // 2FA is enabled
      hide('#login');
      show('#login-2fa');
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
    hide('#login-2fa');
    clearInput('login-2fa-code');
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

// There are many "form" elements in index.html.
// This provides handling of the "submit" event for the form with a given id.
// It changes the cursor to a wait cursor while the handler function runs and
// changes it back to a default cursor when the handler function completes.
// It also provides generic error handling.
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

// Registers a new user.
async function register() {
  const email = getValue('register-email');
  const role = getValue('register-role');
  const password = getValue('register-password');
  const confirmPassword = getValue('register-confirm-password');
  if (confirmPassword === password) {
    try {
      await postJson('user', {email, password, role});
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

// Sets the cursor for the enter UI,
// including when hovering over all buttons.
function setCursor(form, cursor) {
  document.body.style.cursor = cursor;
  const buttons = form.querySelectorAll('button');
  for (const button of buttons) {
    button.style.cursor = cursor;
  }
}

// This changes the UI based on whether a user is currently logged in.
// Whether a user is logged in is saved in sessionStorage
// so it is not lost if the user refreshes their browser.
function setLoggedIn(loggedIn) {
  if (loggedIn) {
    sessionStorage.setItem('authenticated', 'true');
    show('.protected');
    hide('#forgot-password');
    hide('#login');
    show('#change-password');
    show('#enable-2fa');
    show('#logout');
    show('#unregister');
  } else {
    sessionStorage.removeItem('authenticated');
    hide('.protected');
    hide('#change-password');
    hide('#enable-2fa');
    hide('#logout');
    hide('#unregister');
    show('#forgot-password');
    show('#login');
    show('#login-2fa');
  }

  hide('#login-2fa');
}

// Shows all elements that match a given selector.
function show(selector) {
  const elements = document.querySelectorAll(selector);
  for (const element of elements) {
    element.style.display = 'block';
  }
}

// Unregisters the currently logged in user.
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
  // Configure event handling for all the "form" elements on the page.
  onSubmit('change-password', changePassword);
  onSubmit('login', login);
  onSubmit('logout', logout);
  onSubmit('register', register);
  onSubmit('unregister', unregister);
  onSubmit('forgot-password', forgotPassword);
  onSubmit('login-2fa', login2FA);
  onSubmit('delete-user', deleteUser);
  onSubmit('delete-user-sessions', deleteUserSessions);

  // Restore whether a user is currently logged in from the
  // last value in sessionStorage which survives browser refreshes.
  setLoggedIn(sessionStorage.getItem('authenticated') === 'true');
};
