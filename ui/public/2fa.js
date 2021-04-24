window.onload = setup;

let secret;

function getValue(id) {
  return document.getElementById(id).value;
}

async function register2FA(event) {
  event.preventDefault();

  const code = getValue('code');
  console.log('2fa.js register2FA: code =', code);
  console.log('2fa.js register2FA: secret =', secret);
  try {
    await postJson('2fa/register', {code, secret});
    alert('Two-factor authentication has been enabled for this account.');
    location.href = '/'; // return to login page
  } catch (e) {
    console.error('error registering 2FA:', e.message);
    alert('error registering 2FA: ' + e.message);
  }
}

async function setup() {
  const form = document.querySelector('form');
  form.addEventListener('submit', register2FA);

  try {
    const user = await getJson('user');
    console.log('2fa.js setup: user =', user);
    const {otplib, QRCode} = window;
    const serviceName = 'Node Auth Demo';
    secret = otplib.authenticator.generateSecret();
    const otpAuth = otplib.authenticator.keyuri(
      user.email,
      serviceName,
      secret
    );
    const imageUrl = await QRCode.toDataURL(otpAuth);

    const qrWrapper = document.getElementById('qr-wrapper');
    const img = document.createElement('img');
    img.src = imageUrl;
    qrWrapper.appendChild(img);
  } catch (e) {
    alert('You must login to configure 2FA.');
    console.log('error in 2FA setup:', e);
  }
}
