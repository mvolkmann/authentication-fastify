# authentication-fastify

This demonstrates user management using Node.js and Fastify.
It is based on ideas from the Level Up Tutorials courses
"Node Fundamentals Authentication" and "Level 2 Node Authentication".

This app sends email using a Gmail account
I created specifically for this purpose.
After creating the account, I had to opt into
"Less secure app access" by following these steps:

- browse gmail.com
- switch to the new account
- click the settings cog in the upper-right
- click the user icon in the upper-right
- click "Manage your Google Account"
- click "Security" in the left nav
- scroll to "Less secure app access"
- click the "Allow less secure apps" toggle

To build and start the API server which listens on port 1919:

- `cd api`
- `npm install`
- `npm start`

To start the Caddy server which provides support for using HTTPS:

- cd to the root project directory
- `caddy start`

API requests should be sent to `https://api.nodeauth.dev`.

To start the UI server which listens on port 5000:

- `cd ui`
- `npm start`
- browse nodeauth.dev, NOT localhost:5000!

To register a new account, supply email and
matching values for "Password" and "Confirm Password".

To change password, first login and then supply email and
matching values for "Confirm Password" and "New Password"
before pressing the "Change Password" button.

To reset password when forgotten, supply email
and press the "Forgot Password" button.
This sends an email containing a "Reset Password" link.
Click the link to go to a page where you can enter a new password.
