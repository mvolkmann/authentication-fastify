# authentication-fastify

This demonstrates user management using Node.js and Fastify.
It is based on ideas from the Level Up Tutorials courses
"Node Fundamentals Authentication" and "Level 2 Node Authentication".

To build and start the API server which listens on port 1919:

- `cd api`
- `npm install`
- `npm start`

To start the Caddy server which provides support for using HTTPS:

- `caddy start`

API requests should be sent to `https://api.nodeauth.dev`.

To start the UI server which listens on port 5000:

- `cd ui`
- `npx serve`
- browse nodeauth.dev
