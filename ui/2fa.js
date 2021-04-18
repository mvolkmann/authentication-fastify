window.onload = setup;

let secret;

function sendToken() {
  const tokenInput = document.getElementById('token-input');
  const token = tokenInput.value;
  postJson('2fa/register', {secret, token});
}

async function setup() {
  const submitBtn = document.getElementById('submit-btn');
  submitBtn.addEventListener('click', sendToken);

  try {
    const user = await getJson('user');
    console.log('2fa.js setup: user =', user);
    //const {otplib, QRCode} = window;
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
    console.log('error in 2FA setup:', e);
  }
}
