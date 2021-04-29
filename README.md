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

To change password, first login and then supply
email, current password, and new password
before pressing the "Change Password" button.

To reset password when forgotten, supply email
and press the "Forgot Password" button.
This sends an email containing a "Reset Password" link.
Click the link to go to a page where you can enter a new password.

To enable two-factor authentication,
click the link and follow the instructions that are displayed.
This requires use of a mobile authenticator app like "Google Authenticator".
After enabling this, subsequent logins
with the email address of the current user will require
email, password, and a code from the authenticator app.

To unregister the account of the currently logged in user,
press the "Unregister" button.

If the logged in user has the "admin" role,
you can delete all the sessions of a user with a given email address
by entering it and pressing the "Delete User Sessions" button.

If the logged in user has the "admin" role,
you can delete all the user with a given email address and all their sessions
by entering the email address and pressing the "Delete User" button.

The "Unprotected Page" link at the bottom can be clicked and
will display "This is unprotected data." for any user.
It will even work if no user is logged in.
However, the "Protected Page" link at the bottom
will only be displayed if a user is logged in.
Clicking the link will display "This is protected data".
If you attempt browse the URL <https://nodeauth.dev/protected.html>
and are not logged in, you will see "Access to protected data was blocked."
