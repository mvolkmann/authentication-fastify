import {authenticator} from '@otplib/preset-default';
import bcrypt from 'bcryptjs';
import crypto, {randomBytes} from 'crypto'; // in Node.js
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import mongo from 'mongodb';
import nodemailer from 'nodemailer';
//import sendmailSetup from 'sendmail';

import {getCollection} from './db.js';

const {compare, genSalt, hash} = bcrypt;

const {ObjectID} = mongo;

const ACCESS_TOKEN_MINUTES = 1; // expire after this
const FROM_EMAIL = 'r.mark.volkmann@gmail.com';
const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const REFRESH_TOKEN_DAYS = 7; // expire after this
const SESSION_TOKEN_LENGTH = 50;
const VERIFY_MINUTES = 10;

//const sendmail = sendmailSetup();

// Load environment variables from the .env file into process.env.
// JWT_SIGNATURE is a hard-to-guess string.
dotenv.config();
const {JWT_SIGNATURE, ROOT_DOMAIN} = process.env;

// Making cookies httpOnly prevents client-side scripts
// and browser extensions from accessing them.
// Making cookies "secure" requires the use of HTTPS
// to transmit them instead of HTTP.
const COOKIE_OPTIONS = {
  domain: ROOT_DOMAIN,
  httpOnly: true,
  path: '/', // relative to the domain?
  secure: true
};

let mail; // set to result of nodemailer.createTransport call

export async function changePassword(request, reply) {
  const {email, oldPassword, newPassword} = request.body;
  const unencodedEmail = decodeURIComponent(email);

  try {
    // This verifies that the user is currently authenticated
    // and gets their current hashed password.
    const user = await getUser(request, reply);

    // Hash "oldPassword" and compare it to the current hashed password.
    const matches = await compare(oldPassword, user.password);
    if (matches) {
      const hashedPassword = await hashPassword(newPassword);

      // Update the record in the "user" collection
      // that matches the specified email,
      // replacing the current password with the new one.
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

export async function configureEmail() {
  /*
  // This sends an email message using Ethereal.
  // From https://ethereal.email, "Ethereal is a fake SMTP service,
  // mostly aimed at Nodemailer users (but not limited to).
  // It's a completely free anti-transactional email service
  // where messages never get delivered."

  // Create an account to use with Ethereal.
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
  */

  // This sends an email using a Gmail account.
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS
    }
  });
}

// If "expires" is not provided,
// the cookie expires at the end of the session.
function createCookie(reply, name, data, expires) {
  reply.setCookie(name, data, {...COOKIE_OPTIONS, expires});
}

export async function createSession(request, reply, user) {
  // Create a random session token using the crypto module.
  // We could use a UUID created by the npm package "uuid" instead.
  const sessionToken = randomBytes(SESSION_TOKEN_LENGTH).toString('hex');

  try {
    // Insert a record into the "session" collection.
    await getCollection('session').insertOne({
      createdAt: new Date(),
      sessionToken,
      updatedAt: new Date(),
      userAgent: request.headers['user-agent'],
      userId: user._id,
      valid: true
    });
    // Create cookies containing access and refresh tokens.
    await createTokens(user._id, sessionToken, reply);
  } catch (e) {
    console.error('createSession error:', e);
    throw new Error('session creation failed');
  }
}

// Creates a JSON Web Token (JWT).
function createJwt(...data) {
  const delimiter = ':';
  return crypto
    .createHash('sha256')
    .update(JWT_SIGNATURE + delimiter + data.join(delimiter))
    .digest('hex');
}

// Creates cookies containing access and refresh tokens.
export async function createTokens(userId, sessionToken, reply) {
  try {
    const accessToken = jwt.sign({userId, sessionToken}, JWT_SIGNATURE);
    let expires = new Date();
    expires.setMinutes(expires.getMinutes() + ACCESS_TOKEN_MINUTES);
    createCookie(reply, 'access-token', accessToken, expires);

    const refreshToken = jwt.sign({sessionToken}, JWT_SIGNATURE);
    expires = new Date();
    expires.setDate(expires.getDate() + REFRESH_TOKEN_DAYS);
    createCookie(reply, 'refresh-token', refreshToken, expires);
  } catch (e) {
    console.error('createTokens error:', e);
    throw new Error('error refreshing tokens');
  }
}

export async function createUser(request, reply) {
  const {email, password, role} = request.body;
  try {
    const hashedPassword = await hashPassword(password);

    // Insert a record into the "user" collection.
    await getCollection('user').insertOne({
      email,
      password: hashedPassword,
      role,
      verified: false
    });

    // After successfully creating a new user, automatically log in.
    await login(request, reply);

    // Send email to user containing a link
    // they can click to verify their account.
    // Some operations could require the user to be verified.
    await sendVerifyEmail(email);
  } catch (e) {
    console.error('createUser error:', e);
    reply.code(500).send(e.message);
  }
}

export async function deleteCurrentUser(request, reply) {
  try {
    // This verifies that the user is currently authenticated
    // and gets their email.
    const user = await getUser(request, reply);

    // Delete all records from the "user" collection
    // that have the email address of the current user.
    await getCollection('user').deleteMany({email: user.email});

    reply.send('user deleted');
  } catch (e) {
    console.error('deleteCurrentUser error:', e);
    reply.code(500).send('error deleting user');
  }
}

// Only admin users should be able to invoke this.
export async function deleteUser(request, reply) {
  const {email} = request.params;

  try {
    const currentUser = await getUser(request, reply);
    if (currentUser.role !== 'admin') {
      reply.code(401).send('Only admin users can delete another user.');
      return;
    }

    // Get the record from the "user" collection with the specified email.
    const user = await getCollection('user').findOne({email});
    if (user) {
      const id = ObjectID(user._id);

      // Delete all records from the "session" collection
      // that have the id of the current user.
      await getCollection('session').deleteMany({userId: id});

      // Delete all records from the "user" collection
      // that have the id of the current user.
      // There should only be one.
      await getCollection('user').deleteMany({_id: id});

      // NOTE:
      // The user will be able to continue calling
      // services until their access token expires.
      // Subsequent requests will attempt to use their refresh token
      // to create a new access token, but this will fail because
      // all their session records will have been deleted.
      // Recall that a benefit of using both access and refresh tokens
      // is that access token checks can be very fast
      // because the only check that the token is valid.

      reply.send('user deleted');
    } else {
      // No matching "user" record was found.
      reply.code(404).send();
    }
  } catch (e) {
    console.error('deleteUser error:', e);
    reply.code(500).send('error deleting user');
  }
}

// Only admin users should be able to invoke this.
export async function deleteUserSessions(request, reply) {
  const {email} = request.params;

  try {
    const currentUser = await getUser(request, reply);
    if (currentUser.role !== 'admin') {
      reply.code(401).send('Only admin users can delete user sessions.');
      return;
    }

    // Get the record from the "user" collection with the specified email.
    const user = await getCollection('user').findOne({email});
    if (user) {
      // Delete all records from the "session" collection
      // that have the id of the user with the specified email.
      await getCollection('session').deleteMany({userId: ObjectID(user._id)});

      // See NOTE in the deleteUser function above.

      reply.send('user sessions deleted');
    } else {
      // No matching "user" record was found.
      reply.code(404).send();
    }
  } catch (e) {
    console.error('deleteUserSessions error:', e);
    reply.code(500).send('error deleting user sessions');
  }
}

export async function forgotPassword(request, reply) {
  const {email} = request.params;
  try {
    // Get the record from the "user" collection with the specified email.
    const user = await getCollection('user').findOne({email});
    if (user) {
      // Create a password reset link to be included in an email message.
      // The "/user/reset" REST service called from password-reset.js
      // verifies that the "email" and "expires" values
      // passed as query parameters match those found in the JWT.
      // So it is not possible to use an expired link
      // by simply changing the "expires" query parameter.
      const encodedEmail = encodeURIComponent(email);
      const expires = Date.now() + ONE_DAY_MS;
      const token = createJwt(email, expires);
      const link =
        `https://${ROOT_DOMAIN}/password-reset.html` +
        `?email=${encodedEmail}&expires=${expires}&token=${token}`;

      // Send an email containing a link that can be clicked
      // to reset the password of the associated user.
      const subject = 'Reset your password';
      const html =
        'Click the link below to reset your password.<br><br>' +
        `<a href="${link}">RESET PASSWORD</a>`;
      await sendEmail({to: email, subject, html});
    }

    // Return a success status even if user doesn't exist
    // so bots cannot use this service to determine
    // whether a user with a specified email exists.
    reply.send();
  } catch (e) {
    console.error('forgotPassword error:', e);
    reply.code(500).send('error sending password reset email');
  }
}

export async function getNewPassword(request, reply) {
  const {email, expires, token} = request.params;
  // Redirect the browser to the "Password Reset" page,
  // including query parameters that are needed
  // to validate a password reset request.
  reply.redirect(
    `https://${ROOT_DOMAIN}/password-reset.html/${email}/${expires}/${token}`
  );
}

export async function getUser(request, reply) {
  const accessToken = request.cookies['access-token'];
  if (accessToken) {
    // Verify that the access token is valid and decode it.
    // This throws if accessToken is not valid.
    const decodedAccessToken = jwt.verify(accessToken, JWT_SIGNATURE);

    // Get the record from the "user" collection
    // with an id matching the one in the access token.
    const user = await getCollection('user').findOne({
      _id: ObjectID(decodedAccessToken.userId)
    });
    return user;
  } else {
    const refreshToken = request.cookies['refresh-token'];
    if (refreshToken) {
      // Verify that the refresh token is valid and decode it.
      // This throws if refreshToken is not valid.
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);

      // Get the record from the "session" collection
      // with a session token matching the one in the refresh token.
      const {sessionToken} = decodedRefreshToken;
      const session = await getCollection('session').findOne({sessionToken});

      if (session && session.valid) {
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

// This wraps the getUser function as a REST service.
export async function getUserService(request, reply) {
  try {
    const user = await getUser(request, reply);
    if (user) {
      reply.send(user);
    } else {
      reply.code(404).send();
    }
  } catch (e) {
    reply.code(400).send(e.message);
  }
}

async function hashPassword(password) {
  // Defaults to 10 rounds.
  // We use a different value so it can't be easily guessed.
  const salt = await genSalt(9);
  return hash(password, salt);
}

export async function login(request, reply) {
  const {email, password} = request.body;
  try {
    // Get the record from the "user" collection with the specified email.
    const user = await getCollection('user').findOne({email});

    // If the user exists and their password matches the specified one ...
    if (user && (await verifyPassword(user, password))) {
      // If the user has enabled two-factor authentication (2FA) ...
      if (user.secret) {
        // Don't login until a 2FA code is provided.
        reply.send({userId: user._id, status: '2FA'});
      } else {
        // 2FA is not enabled for this account,
        // so create a new session for this user.
        await createSession(request, reply, user);

        reply.send('logged in');
      }
    } else {
      reply.code(401).send('invalid email or password');
    }
  } catch (e) {
    console.error('login error:', e);
    reply.code(500).send(e.message);
  }
}

export async function login2FA(request, reply) {
  const {code, email, password} = request.body;
  try {
    // Get the record from the "user" collection with the specified email.
    const user = await getCollection('user').findOne({email});

    // If the user exists and
    // their password matches the specified one and
    // the 2FA code generated using their secret matches the specified code ...
    if (
      user &&
      verifyPassword(user, password) &&
      verify2FA(user.secret, code)
    ) {
      // Create a new session for this user.
      await createSession(request, reply, user);

      reply.send('logged in');
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
    const refreshToken = request.cookies['refresh-token'];
    if (refreshToken) {
      // Get the session token from the refresh token.
      // This throws if refreshToken is not valid.
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);
      const {sessionToken} = decodedRefreshToken;

      // Delete the record from the "session" collection
      // that has a matching session token.
      await getCollection('session').deleteOne({sessionToken});
    }

    // Clear the access and refresh token cookies for this session.
    reply
      .clearCookie('access-token', COOKIE_OPTIONS)
      .clearCookie('refresh-token', COOKIE_OPTIONS);

    reply.send('logged out');
  } catch (e) {
    console.error('logout error:', e.message);
    reply.code(500).send(e.message);
  }
}

export async function register2FA(request, reply) {
  const {code, secret} = request.body;

  try {
    // Get the user associated with the current session.
    const user = await getUser(request, reply);

    // If the user exists and
    // the 2FA code generated using the secret matches the specified code ...
    if (user && verify2FA(secret, code)) {
      // Update the record in the "user" collection with the "secret"
      // so it can be used for 2FA logins in the future.
      await getCollection('user').updateOne(
        {email: user.email},
        {$set: {secret}}
      );

      reply.send('registered for 2FA');
    } else {
      reply.code(401).send();
    }
  } catch (e) {
    console.error('register2fa error:', e);
    reply.code(500).send('error registering 2FA: ' + e.message);
  }
}

export async function resetPassword(request, reply) {
  const {email, expires, password, token} = request.body;

  // Determine if the token matches the
  // specified email and expires timestamp.
  const matches = token === createJwt(email, expires);

  // If the token does not match or is expired ...
  if (!matches || Date.now() > expires) {
    reply.code(400).send('password reset link expired');
    return;
  }

  try {
    // Update the record in the "user" collection
    // with a new hashed password.
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
}

export async function sendEmail({from = FROM_EMAIL, to, subject, html}) {
  // If sending of email has not yet been configured ...
  if (!mail) mail = await configureEmail();

  return mail.sendMail({from, to, subject, html});

  //const info = await mail.sendMail({from, to, subject, html});
  // Output the URL where the Ethereal email can be viewed.
  //console.log('email preview URL =', nodemailer.getTestMessageUrl(info));

  // This approach supposedly doesn't require an SMTP server,
  // but I couldn't get it to work.  It produced a lot of output
  // that indicates it worked, but I never receive the email.
  /*
  sendmail({from, to, subject, html}, (err, reply) => {
    console.log('api.js sendEmail: err =', err);
    console.log('api.js sendEmail: reply =', reply);
  });
  */
}

function sendVerifyEmail(email) {
  // Create a user verify link to be included in an email message.
  const domain = 'api.' + ROOT_DOMAIN;
  const encodedEmail = encodeURIComponent(email);
  const expires = new Date();
  expires.setMinutes(expires.getMinutes() + VERIFY_MINUTES);
  const expiresMs = expires.getTime();
  const emailToken = createJwt(email, expiresMs);
  const link =
    `https://${domain}/verify/` + `${encodedEmail}/${expiresMs}/${emailToken}`;

  // Send an email containing a link that can be clicked
  // to verify the associated user.
  const subject = 'Verify your account';
  const html =
    'Click the link below to verify your account.<br><br>' +
    `<a href="${link}">VERIFY</a>`;
  return sendEmail({to: email, subject, html});
}

// Verifies that the code generated from a 2FA secret matches a given code.
const verify2FA = (secret, code) => authenticator.verify({secret, token: code});

export async function verifyUser(request, reply) {
  const {email, expires, token} = request.params;

  // Determine if the token matches the
  // specified email and expires timestamp.
  const matches = token === createJwt(decodeURIComponent(email), expires);

  // If the token does not match or is expired ...
  if (!matches || Date.now() > expires) {
    reply.code(400).send('verify link expired');
    return;
  }

  try {
    // Update the record in the "user" collection
    // that matches the specified email,
    // changing the verified property to true.
    await getCollection('user').updateOne(
      {email: decodeURIComponent(email)},
      {$set: {verified: true}}
    );

    // Navigate to teh login page.
    reply.redirect('https://' + ROOT_DOMAIN);
  } catch (e) {
    console.error('verifyUser error:', e);
    reply.code(500).send('error verifying user: ' + e.message);
  }
}

function verifyPassword(user, password) {
  const hashedPassword = user.password;
  // Hash "password" and compare it to the current hashed password.
  return compare(password, hashedPassword); // returns a Promise
}
