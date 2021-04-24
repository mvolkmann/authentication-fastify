import {fastify} from 'fastify';
import fastifyCookie from 'fastify-cookie';
import fastifyCors from 'fastify-cors';
//import fastifyStatic from 'fastify-static';
//import path from 'path';
//import {fileURLToPath} from 'url';

import {
  changePassword,
  createUser,
  deleteCurrentUser,
  deleteUser,
  deleteUserSessions,
  forgotPassword,
  getNewPassword,
  getUser,
  getUserService,
  login,
  login2FA,
  logout,
  register2FA,
  resetPassword,
  verifyUser
} from './auth.js';
import {connect} from './db.js';

const PORT = 1919;

//const app = fastify({logger: true});
const app = fastify(); // no request logging

async function getProtectedData(request, reply) {
  try {
    // There are built-in ways in Fastify
    // to verify that the user is authenticated,
    // but we are doing it manually to demonstrate the steps.
    await getUser(request, reply);
    reply.send({data: 'This is protected data.'});
  } catch (e) {
    console.error('server.js getProtectedData: e =', e);
    reply.code(401).send();
  }
}

function getUnprotectedData(request, reply) {
  reply.send({data: 'This is unprotected data.'});
}

async function startApp() {
  try {
    // Add support for Cross Origin Resource Sharing.
    app.register(fastifyCors, {
      credentials: true, // required to return cookies
      origin: [
        // origin of requests from UI;
        // leading dot means to allow use in subdomains
        /\.nodeauth\.dev$/,
        'https://nodeauth.dev'
      ]
    });

    // Add support for setting and getting cookies.
    app.register(fastifyCookie, {
      secret: process.env.COOKIE_SIGNATURE
    });

    /*
    // Normally these names are defined by Node.js.
    // But when "type" is set to "module" in package.json, these go away.
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // Serve static files from the "public" directory.
    app.register(fastifyStatic, {
      root: path.join(__dirname, 'public')
    });
    */

    app.get('/', {}, (request, reply) => {
      reply.send('server has a heartbeat');
    });

    app.post('/login', {}, login);
    app.get('/logout', {}, logout);

    app.get('/protected', {}, getProtectedData);
    app.get('/unprotected', {}, getUnprotectedData);

    app.get('/user', {}, getUserService);
    app.get('/user/forgot-password/:email', {}, forgotPassword);
    app.post('/user/password', {}, changePassword);
    app.post('/user', {}, createUser);
    app.delete('/user', {}, deleteCurrentUser);
    app.delete('/user/:email', {}, deleteUser);
    app.delete('/user/:email/sessions', {}, deleteUserSessions);
    app.get('/user/reset/:email/:expires/:token', {}, getNewPassword);
    app.post('/user/reset', {}, resetPassword);

    app.get('/verify/:email/:expires/:token', {}, verifyUser);

    app.post('/2fa/register', {}, register2FA);
    app.post('/2fa/login', {}, login2FA);

    await app.listen(PORT);
    console.info('listening on port', PORT);
  } catch (e) {
    console.error('error starting server:', e.message);
  }
}

connect().then(startApp);
