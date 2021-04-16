const URL_PREFIX = 'https://api.nodeauth.dev/';

let confirmPasswordInput;
let passwordInput;
let resetPasswordBtn;

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

async function resetPassword() {
  const [, , email, expires, token] = window.location.pathname.split('/');
  console.log('ui.js resetPassword: email =', email);
  console.log('ui.js resetPassword: expires =', expires);
  console.log('ui.js resetPassword: token =', token);

  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  if (confirmPassword === password) {
    try {
      await postJson('user/reset', {
        email: decodeURIComponent(email),
        expires,
        password,
        token
      });
      alert('Password reset');
    } catch (e) {
      console.error('resetPassword error:', e);
      alert('Password reset failed');
    }
  }
}

window.onload = () => {
  confirmPasswordInput = document.getElementById('confirm-password');
  passwordInput = document.getElementById('password');
  resetPasswordBtn = document.getElementById('reset-password-btn');

  resetPasswordBtn.addEventListener('click', resetPassword);
};
