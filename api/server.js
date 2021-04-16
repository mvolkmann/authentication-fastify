import {fastify} from 'fastify';
import fastifyCookie from 'fastify-cookie';
import fastifyCors from 'fastify-cors';
import fastifyStatic from 'fastify-static';
import path from 'path';
import {fileURLToPath} from 'url';

import {
  changePassword,
  createUser,
  deleteUser,
  forgotPassword,
  getUser,
  login,
  logout,
  resetPassword,
  verifyUser
} from './auth.js';
import {connect} from './db.js';

// Normally these names are defined by Node.js.
// But when "type" is set to "module" in package.json,
// these go away.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 1919;

//const app = fastify({logger: true});
const app = fastify(); // no request logging

async function test(request, reply) {
  // There are built-in ways to do this in Fastify,
  // but we are doing it manually to demonstrate the steps.
  try {
    const user = await getUser(request, reply);

    if (user?._id) {
      reply.send('user session found');
    } else {
      reply.status(400).send('no user session found');
    }
  } catch (e) {
    console.error(e);
    throw new Error('failed to get session: ' + e.message);
  }
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

    // Serve static files from the "public" directory.
    // Browse localhost:1919/demo to test all the REST services.
    app.register(fastifyStatic, {
      root: path.join(__dirname, 'public')
    });

    app.get('/', {}, (request, reply) => {
      reply.send('server has a heartbeat');
    });

    app.get('/user/forgot-password/:email', {}, forgotPassword);
    app.post('/user/password', {}, changePassword);
    app.post('/user', {}, createUser);
    app.delete('/user/:email', {}, deleteUser);
    app.post('/login', {}, login);
    //TODO: Does this need to be a POST?
    //TODO: Verify that the /test route fails when called after logout.
    app.get('/logout', {}, logout);
    app.get('/verify/:email/:token', {}, verifyUser);
    app.get('/user/reset/:email/:token', {}, resetPassword);

    // This demonstrates implementing a protected route.
    app.get('/test', {}, test);

    await app.listen(PORT);
    console.info('listening on port', PORT);
  } catch (e) {
    console.error('error starting server:', e.message);
  }
}

connect().then(startApp);
