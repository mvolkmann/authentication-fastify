import {authenticator} from '@otplib/preset-default';
import bcrypt from 'bcryptjs';
import crypto, {randomBytes} from 'crypto'; // in Node.js
import dotenv from 'dotenv';
import mongo from 'mongodb';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';

import {getCollection} from './db.js';

const {compare, genSalt, hash} = bcrypt;

const {ObjectID} = mongo;

const FROM_EMAIL = 'r.mark.volkmann@gmail.com';
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

// Load environment variables from the .env file into process.env.
dotenv.config();
const {JWT_SIGNATURE, ROOT_DOMAIN} = process.env;

const COOKIE_OPTIONS = {
  domain: ROOT_DOMAIN,
  httpOnly: true,
  path: '/',
  secure: true
};

let mail;

export async function changePassword(request, reply) {
  const {email, oldPassword, newPassword} = request.body;
  const unencodedEmail = decodeURIComponent(email);
  const user = await getUser(request, reply);

  try {
    const matches = await compare(oldPassword, user.password);
    if (matches) {
      const hashedPassword = await hashPassword(newPassword);
      await getCollection('user').updateOne(
        {email: unencodedEmail},
        {$set: {password: hashedPassword}}
      );
      reply.send('changed password');
    } else {
      reply.code(400).send('invalid email or password');
    }
  } catch (e) {
    console.error('changePassword error:', e);
    reply.code(500).send('error changing password: ' + e.message);
  }
}

function createCookie(reply, name, data, expires) {
  reply.setCookie(name, data, {...COOKIE_OPTIONS, expires});
}

export async function createSession(request, reply, user) {
  // Could use a UUID created by the npm package "uuid" instead.
  const sessionToken = randomBytes(50).toString('hex'); // 50 is length

  //TODO: Add IP address to cookies and validate that
  //TODO: subsequent requests come from that address?
  const {ip} = request;
  console.log('auth.js createSession: ip =', ip);

  const userAgent = request.headers['user-agent'];

  try {
    await getCollection('session').insertOne({
      createdAt: new Date(),
      sessionToken,
      updatedAt: new Date(),
      userAgent,
      userId: user._id,
      valid: true
    });
    await createTokens(user._id, sessionToken, reply);
  } catch (e) {
    console.error(e);
    throw new Error('session creation failed');
  }
}

function createToken(...data) {
  const delimiter = ':';
  return crypto
    .createHash('sha256')
    .update(JWT_SIGNATURE + delimiter + data.join(delimiter))
    .digest('hex');
}

export async function createTokens(userId, sessionToken, reply) {
  try {
    const accessToken = jwt.sign({userId, sessionToken}, JWT_SIGNATURE);
    let expires = new Date();
    expires.setMinutes(expires.getMinutes() + 10); // expires in 10 minutes
    createCookie(reply, 'access-token', accessToken, expires);

    const refreshToken = jwt.sign({sessionToken}, JWT_SIGNATURE);
    expires = new Date();
    expires.setDate(expires.getDate() + 7); // expires in one week
    createCookie(reply, 'refresh-token', refreshToken, expires);
  } catch (e) {
    console.error(e);
    throw new Error('error refreshing tokens');
  }
}

export async function createUser(request, reply) {
  const {email, password} = request.body;
  try {
    const hashedPassword = await hashPassword(password);
    const res = await getCollection('user').insertOne({
      email,
      password: hashedPassword,
      verified: false
    });

    // After successfully creating a new user,
    // automatically log in.
    await login(request, reply);

    await sendVerifyEmail(email);
  } catch (e) {
    reply.code(500).send(e.message);
  }
}

export async function deleteCurrentUser(request, reply) {
  const user = await getUser(request, reply);
  try {
    await getCollection('user').deleteMany({email: user.email});
    reply.send('user deleted');
  } catch (e) {
    reply.code(500).send('error deleting user');
  }
}

// Only admin users should be able to invoke this.
export async function deleteUser(request, reply) {
  const {email} = request.params;
  try {
    const user = await getCollection('user').findOne({email});
    if (user) {
      const id = ObjectID(user._id);
      await getCollection('session').deleteMany({userId: id});
      await getCollection('user').deleteMany({_id: id});
      reply.send('user deleted');
    } else {
      reply.code(404).send();
    }
  } catch (e) {
    reply.code(500).send('error deleting user');
  }
}

// Only admin users should be able to invoke this.
export async function deleteUserSessions(request, reply) {
  const {email} = request.params;
  try {
    const user = await getCollection('user').findOne({email});
    if (user) {
      await getCollection('session').deleteMany({userId: ObjectID(user._id)});
      reply.send('user sessions deleted');
    } else {
      reply.code(404).send();
    }
  } catch (e) {
    reply.code(500).send('error deleting user sessions');
  }
}

export async function forgotPassword(request, reply) {
  const {email} = request.params;
  try {
    const user = await getCollection('user').findOne({email});
    if (user) {
      const encodedEmail = encodeURIComponent(email);
      const expires = Date.now() + ONE_DAY_MS;
      const token = createToken(email, expires);
      const link = `https://${ROOT_DOMAIN}/password-reset.html?email=${encodedEmail}&expires=${expires}&token=${token}`;
      const subject = 'Reset your password';
      const html =
        'Click the link below to reset your password.<br><br>' +
        `<a href="${link}">RESET PASSWORD</a>`;
      await sendEmail({to: email, subject, html});
    }

    // Returning success status even if user doesn't exist
    // so bots cannot use this service to
    // determine whether a user with a given email exists.
    reply.send();
  } catch (e) {
    reply.code(500).send('error sending password reset email');
  }
}

export async function getNewPassword(request, reply) {
  const {email, expires, token} = request.params;
  reply.redirect(
    `https://${ROOT_DOMAIN}/password-reset.html/${email}/${expires}/${token}`
  );
}

export async function getUser(request, reply) {
  const accessToken = request?.cookies?.['access-token'];
  if (accessToken) {
    const decodedAccessToken = jwt.verify(accessToken, JWT_SIGNATURE);

    // Return the user.
    const user = await getCollection('user').findOne({
      _id: ObjectID(decodedAccessToken.userId)
    });
    return user;
  } else {
    const refreshToken = request?.cookies?.['refresh-token'];
    if (refreshToken) {
      // Find the session associated with this refresh token.
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);
      const {sessionToken} = decodedRefreshToken;
      const session = await getCollection('session').findOne({sessionToken});
      if (session.valid) {
        // Find the user associated with this session.
        const user = await getCollection('user').findOne({
          _id: ObjectID(session.userId)
        });
        if (!user) throw new Error('user not found');

        // Create new access and refresh tokens for this session.
        await createTokens(session.userId, sessionToken, reply);
        return user;
      } else {
        throw new Error('no valid session found');
      }
    } else {
      throw new Error('no access token or refresh token found');
    }
  }
}

export async function getUserService(request, reply) {
  const user = await getUser(request, reply);
  if (user) {
    reply.send(user);
  } else {
    reply.code(404).send({});
  }
}

async function hashPassword(password) {
  // Defaults to 10 rounds. Using different value so it can't be guessed.
  const salt = await genSalt(9);
  return hash(password, salt);
}

export async function login(request, reply) {
  const {email, password} = request.body;
  try {
    const user = await getCollection('user').findOne({email});
    if (user && (await verifyPassword(user, password))) {
      if (user.secret) {
        // Don't login until 2FA is provided.
        reply.send({userId: user._id, status: '2FA'});
      } else {
        // 2FA is not enabled for this account, so login.
        await createSession(request, reply, user);
        reply.send();
      }
    } else {
      reply.code(401).send('invalid email or password');
    }
  } catch (e) {
    reply.code(500).send(e.message);
  }
}

export async function login2FA(request, reply) {
  const {code, email, password} = request.body;
  try {
    const user = await getCollection('user').findOne({email});
    if (
      user &&
      verifyPassword(user, password) &&
      verify2FA(user.secret, code)
    ) {
      await createSession(request, reply, user);
      console.log('auth.js login2FA: authenticated');
      reply.send();
    } else {
      reply.code(400).send('invalid 2FA code');
    }
  } catch (e) {
    console.error('login2FA error:', e);
    reply.code(500).send('error verifying 2FA: ' + e.message);
  }
}

export async function logout(request, reply) {
  try {
    const refreshToken = request?.cookies?.['refresh-token'];
    if (refreshToken) {
      // Delete the associated session.
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);
      const {sessionToken} = decodedRefreshToken;
      await getCollection('session').deleteOne({sessionToken});
    }

    // Clear both cookies for this session.
    reply
      .clearCookie('access-token', COOKIE_OPTIONS)
      .clearCookie('refresh-token', COOKIE_OPTIONS);

    reply.send('user logged out');
  } catch (e) {
    console.error('auth.js logout:', e.message);
    reply.code(500).send(e.message);
  }
}

export async function register2FA(request, reply) {
  try {
    const user = await getUser(request, reply);
    const {code, secret} = request.body;
    if (user && verify2FA(secret, code)) {
      await getCollection('user').updateOne(
        {email: user.email},
        {$set: {secret}}
      );
      reply.send('registered for 2FA');
    } else {
      reply.code(401).send();
    }
  } catch (e) {
    console.error('auth.js register2fa: error =', e);
    reply.code(500).send('error registering 2FA: ' + e.message);
  }
}

export async function resetPassword(request, reply) {
  const {email, expires, password, token} = request.body;
  const tokenValid = token === createToken(email, expires);

  if (Date.now() > expires || !tokenValid) {
    reply.code(400).send('password reset expired');
    return;
  }

  try {
    const hashedPassword = await hashPassword(password);
    await getCollection('user').updateOne(
      {email},
      {$set: {password: hashedPassword}}
    );
    reply.send('password reset');
  } catch (e) {
    console.error('resetPassword error:', e);
    reply.code(500).send('error resetting password: ' + e.message);
  }
  //} else {
  //  reply.code(401).send('password reset failed');
  //}
}

export async function sendEmail({from = FROM_EMAIL, to, subject, html}) {
  try {
    if (!mail) mail = await setupEmail();

    const info = await mail.sendMail({from, to, subject, html});
    console.log(
      'auth.js sendEmail: preview URL =',
      nodemailer.getTestMessageUrl(info)
    );
  } catch (e) {
    console.error('sendEmail error:', e);
  }
}

export async function sendVerifyEmail(email) {
  try {
    const encodedEmail = encodeURIComponent(email);
    const emailToken = createToken(email);
    const domain = 'api.' + ROOT_DOMAIN;
    const link = `https://${domain}/verify/${encodedEmail}/${emailToken}`;
    const subject = 'Verify your account';
    const html =
      'Click the link below to verify your account.<br><br>' +
      `<a href="${link}">VERIFY</a>`;
    await sendEmail({to: email, subject, html});
  } catch (e) {
    console.error('verifyAccount error:', e);
  }
}

export async function setupEmail() {
  try {
    const testAccount = await nodemailer.createTestAccount();
    return nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass
      }
    });
  } catch (e) {
    console.error('sendEmail error:', e);
  }
}

function verify2FA(secret, code) {
  return authenticator.verify({secret, token: code});
}

export async function verifyUser(request, reply) {
  const {email, token} = request.params;
  const unencodedEmail = decodeURIComponent(email);
  const emailToken = createToken(unencodedEmail);
  if (token === emailToken) {
    try {
      await getCollection('user').updateOne(
        {email: unencodedEmail},
        {$set: {verified: true}}
      );
      reply.redirect('https://' + ROOT_DOMAIN); // goes to login page
    } catch (e) {
      console.error('verifyUser error:', e);
      reply.code(500).send('error verifying user: ' + e.message);
    }
  } else {
    reply.code(401).send('verifying user failed');
  }
}

function verifyPassword(user, password) {
  const hashedPassword = user.password;
  return compare(password, hashedPassword); // returns a Promise
}
