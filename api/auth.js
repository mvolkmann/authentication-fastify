import bcrypt from 'bcryptjs';
import {randomBytes} from 'crypto'; // in Node.js
import dotenv from 'dotenv';
import mongo from 'mongodb';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';

import {getCollection} from './db.js';

const {compare, genSalt, hash} = bcrypt;

const {ObjectId} = mongo;

const FROM_EMAIL = 'r.mark.volkmann@gmail.com';

// Load environment variables from the .env file into process.env.
dotenv.config();
const {JWT_SIGNATURE} = process.env;

let mail;

function createCookie(reply, name, data, expires) {
  reply.setCookie(name, data, {
    domain: process.env.ROOT_DOMAIN,
    expires,
    httpOnly: true,
    path: '/',
    secure: true
  });
}

export async function createSession(userId, connection) {
  //TODO: Why not use a UUID?
  const sessionToken = randomBytes(50).toString('hex'); // 50 is length
  const {ip, userAgent} = connection;

  try {
    await getCollection('session').insertOne({
      createdAt: new Date(),
      sessionToken,
      updatedAt: new Date(),
      userAgent,
      userId,
      valid: true
    });
    return sessionToken;
  } catch (e) {
    console.error(e);
    throw new Error('session creation failed');
  }
}

export async function createTokens(userId, sessionToken, reply) {
  try {
    const accessToken = jwt.sign({userId, sessionToken}, JWT_SIGNATURE);
    createCookie(reply, 'access-token', accessToken);

    const refreshToken = jwt.sign({sessionToken}, JWT_SIGNATURE);
    const now = new Date();
    const expires = now.setDate(now.getDate() + 7); // one week from now
    createCookie(reply, 'refresh-token', refreshToken, expires);
  } catch (e) {
    console.error(e);
    throw new Error('error refreshing tokens');
  }
}

export async function createUser(request, reply) {
  const {email, password} = request.body;
  try {
    const salt = await genSalt(); // defaults to 10 rounds
    const hashedPassword = await hash(password, salt);
    const res = await getCollection('user').insertOne({
      email,
      password: hashedPassword,
      verified: false
    });

    // After successfully creating a new user,
    // automatically log in.
    await login(request, reply);

    sendEmail({
      to: email,
      subject: 'account created',
      html: 'Please verify your account.'
    });
  } catch (e) {
    reply.status(500).send(e.message);
  }
}

export async function deleteUser(request, reply) {
  const {email} = request.params;
  try {
    await getCollection('user').deleteMany({email});
    reply.send('user deleted');
  } catch (e) {
    reply.status(500).send('error deleting user');
  }
  reply.send('');
}

export async function sendEmail({from: FROM_EMAIL, to, subject, html}) {
  try {
    if (!mail) mail = await setupEmail();

    const info = await mail.sendMail({from, to, subject, html});
    console.log('auth.js sendEmail: info =', info);
  } catch (e) {
    console.error('sendEmail error:', e);
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

export async function getUser(request, reply) {
  const accessToken = request?.cookies?.['access-token'];
  if (accessToken) {
    const decodedAccessToken = jwt.verify(accessToken, JWT_SIGNATURE);

    // Return the user.
    return getCollection('user').findOne({
      _id: ObjectId(decodedAccessToken.userId)
    });
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
          _id: ObjectId(session.userId)
        });
        if (!user) throw new Error('user not found');

        // Create new access and refresh tokens for this session.
        await createTokens(session.userId, sessionToken, reply);
        return user;
      } else {
        throw new Error('no valid session fond');
      }
    } else {
      throw new Error('no access token or refresh token found');
    }
  }
}

export async function login(request, reply) {
  const {email, password} = request.body;
  try {
    const user = await getCollection('user').findOne({email});
    const hashedPassword = user.password;
    const matches = await compare(password, hashedPassword);

    if (matches) {
      const connection = {
        ip: request.ip,
        userAgent: request.headers['user-agent']
      };
      const sessionToken = await createSession(user._id, connection);
      await createTokens(user._id, sessionToken, reply);
      reply.send({userId: user._id});
    } else {
      reply.status(401).send('invalid email or password');
    }
  } catch (e) {
    reply.status(500).send(e.message);
  }
}

export async function logout(request, reply) {
  console.log('auth.js logout: cookies =', request.cookies);
  try {
    const refreshToken = request?.cookies?.['refresh-token'];
    console.log('auth.js logout: refreshToken =', refreshToken);
    if (refreshToken) {
      // Delete the associated session.
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);
      console.log('auth.js logout: decodedRefreshToken =', decodedRefreshToken);
      const {sessionToken} = decodedRefreshToken;
      await getCollection('session').deleteOne({sessionToken});
    }

    // Clear both cookies for this session.
    reply.clearCookie('access-token').clearCookie('refresh-token');

    reply.send('user logged out');
  } catch (e) {
    console.error('auth.js logout:', e.message);
    reply.status(500).send(e.message);
  }
}
