let confirmPasswordInput;
let passwordInput;
let resetPasswordBtn;

async function resetPassword() {
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  if (confirmPassword === password) {
    const params = new URLSearchParams(window.location.search);
    try {
      await postJson('user/reset', {
        email: decodeURIComponent(params.get('email')),
        expires: params.get('expires'),
        password,
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
  confirmPasswordInput = document.getElementById('confirm-password');
  passwordInput = document.getElementById('password');
  resetPasswordBtn = document.getElementById('reset-password-btn');

  resetPasswordBtn.addEventListener('click', resetPassword);
};
