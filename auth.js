import bcrypt from 'bcryptjs';
import {randomBytes} from 'crypto'; // in Node.js
import dotenv from 'dotenv';
import mongo from 'mongodb';
import path from 'path';
import jwt from 'jsonwebtoken';
import {fileURLToPath} from 'url';

import {getCollection} from './db.js';

const {compare, genSalt, hash} = bcrypt;

const {ObjectId} = mongo;

// Normally these names are defined by Node.js.
// But when "type" is set to "module" in package.json,
// these go away.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from the .env file into process.env.
dotenv.config();
const JWT_SIGNATURE = process.env.JWT_SIGNATURE;

export async function createSession(userId, connection) {
  //TODO: Why not use a UUID?
  const sessionToken = randomBytes(50).toString('hex'); // 50 is length
  const {ip, userAgent} = connection;

  try {
    const sessionCollection = await getCollection('session');
    await sessionCollection.insertOne({
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
    const refreshToken = jwt.sign({sessionToken}, JWT_SIGNATURE);

    const now = new Date();
    const expires = now.setDate(now.getDate() + 7); // one week
    reply.setCookie('access-token', accessToken, {
      domain: 'localhost',
      expires,
      httpOnly: true,
      path: '/'
    });
    reply.setCookie('refresh-token', refreshToken, {
      domain: 'localhost',
      httpOnly: true,
      path: '/'
    });
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
    const userCollection = getCollection('user');
    const res = await userCollection.insertOne({
      email,
      password: hashedPassword,
      verified: false
    });
    return res.insertedId;
  } catch (e) {
    reply.status(500).text(e.message);
  }
}
export async function deleteUser(request, reply) {
  const {email} = request.params;
  try {
    const userCollection = await getCollection('user');
    await userCollection.deleteMany({email});
    reply.send('user deleted');
  } catch (e) {
    reply.status(500).send('error deleting user');
  }
  reply.send('');
}

export async function getUser(request, reply) {
  try {
    const accessToken = request?.cookies?.['access-token'];
    if (accessToken) {
      const decodedAccessToken = jwt.verify(accessToken, JWT_SIGNATURE);
      console.log('index.js getUser: decodedAccessToken =', decodedAccessToken);

      const userCollection = getCollection('user');
      return userCollection.findOne({_id: ObjectId(decodedAccessToken.userId)});
    } else {
      const refreshToken = request?.cookies?.['access-token'];
      if (refreshToken) {
        //TODO: To test use of refresh token,
        //TODO: delete the access - token cookie in DevTools.
        const decodedRefreshToken = jwt.verify(accessToken, JWT_SIGNATURE);
        console.log(
          'index.js getUser: decodedRefreshToken =',
          decodedRefreshToken
        );
        const {sessionToken} = decodedRefreshToken;
        const sessionCollection = await getCollection('session');
        const session = await sessionCollection.findOne({sessionToken});
        if (session.valid) {
          const user = await userCollection.findOne({
            _id: ObjectId(session.userId)
          });
          if (!user) throw new Error('user not found');
          await createTokens(session.userId, sessionToken, reply);
          return user;
        } else {
          throw new Error('invalid session');
        }
      } else {
        throw new Error('no access token or refresh token found');
      }
    }
  } catch (e) {
    console.error(e);
    throw new Error('error getting user');
  }
}

export async function login(request, reply) {
  const {email, password} = request.body;
  try {
    const userCollection = getCollection('user');
    const user = await userCollection.findOne({email});
    const hashedPassword = user.password;
    const matches = await compare(password, hashedPassword);

    if (matches) {
      const connection = {
        ip: request.ip,
        userAgent: request.headers['user-agent']
      };
      const sessionToken = await createSession(user._id, connection);
      await createTokens(user._id, sessionToken, reply);
      reply.send('user logged in');
    } else {
      reply.status(401).send('invalid email or password');
    }
  } catch (e) {
    reply.status(500).text(e.message);
  }
}

export async function logout(request, reply) {
  try {
    const refreshToken = request?.cookies?.['refresh-token'];
    if (refreshToken) {
      const decodedRefreshToken = jwt.verify(refreshToken, JWT_SIGNATURE);
      const {sessionToken} = decodedRefreshToken;
      const sessionCollection = await getCollection('session');
      await sessionCollection.deleteOne({sessionToken});
    }
    reply.clearCookie('access-token').clearCookie('refresh-token');
    reply.send('user logged out');
  } catch (e) {
    console.error('auth.js logout:', e.message);
    reply.status(500).send(e.message);
  }
}
