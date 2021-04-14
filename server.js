import {fastify} from 'fastify';
import fastifyCookie from 'fastify-cookie';
import fastifyStatic from 'fastify-static';
import path from 'path';
import {fileURLToPath} from 'url';

import {createUser, deleteUser, getUser, login, logout} from './auth.js';
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
    console.log('index.js test route: user =', user);

    if (user?._id) {
      reply.send(user);
    } else {
      reply.send({data: 'user lookup failed'});
    }
  } catch (e) {
    console.error(e);
    throw new Error('error getting user');
  }
}

async function startApp() {
  try {
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

    app.post('/api/user', {}, createUser);
    app.delete('/api/user/:email', {}, deleteUser);
    app.post('/api/login', {}, login);
    //TODO: Does this need to be a POST?
    //TODO: Verify that the /test route fails when called after logout.
    app.get('/api/logout', {}, logout);

    // This demonstrates implementing a protected route.
    app.get('/test', {}, test);

    await app.listen(PORT);
    console.info('listening on port', PORT);
  } catch (e) {
    console.error('error starting server:', e.message);
  }
}

connect().then(startApp);
