function getValue(id) {
  return document.getElementById(id).value;
}

async function resetPassword(event) {
  event.preventDefault();

  const newPassword = getValue('new-password');
  const confirmPassword = getValue('confirm-password');
  if (confirmPassword === newPassword) {
    const params = new URLSearchParams(window.location.search);
    try {
      await postJson('user/reset', {
        email: decodeURIComponent(params.get('email')),
        expires: params.get('expires'),
        password: newPassword,
        token: params.get('token')
      });
      alert('Password reset');
      location.href = '/'; // goes to login page
    } catch (e) {
      console.error('resetPassword error:', e);
      alert('Password reset failed');
    }
  }
}

window.onload = () => {
  const form = document.querySelector('form');
  form.addEventListener('submit', resetPassword);
};
