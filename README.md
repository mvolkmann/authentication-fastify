# authentication-fastify

This application demonstrates user management using Node.js and
[fastify](https://github.com/fastify/fastify) library.
It is useful for learning about patterns in user management
that are not tied to a specific server side programming language
or collection of libraries.
Languages other that JavaScript likely have similar libraries
that can be used to implement the same functionality.

The web UI uses vanilla JavaScript instead of a framework
in order to avoid appealing to users of a particular framework
and to keep the UI simple.

The app is based on concepts I learned from Scott Tolinski's
{% aTargetBlank "https://www.leveluptutorials.com/", "Level Up Tutorials" %}
courses on {% aTargetBlank
"https://www.leveluptutorials.com/tutorials/node-fundamentals-authentication",
"Node Fundamentals Authentication" %} and {% aTargetBlank
"https://www.leveluptutorials.com/tutorials/level-2-node-authentication",
"Level 2 Node Authentication" %}.
I highly recommend checking out these courses
and many others that Scott has created!

For information on the terminology related to this app and
strategies for security passwords, see my blog page on {% aTargetBlank
"https://mvolkmann.github.io/blog/topics/#/blog/authentication/",
"Authentication" %}.

## Libraries

The npm packages used in client side of this app include:

- "@otplib/preset-browser`
- `http-server`
- `qrcode`

The npm packages used in the server side of this app include:

- `@otplib/preset-default`
- `bcryptjs`
- `dotenv`
- `fastify`
- `fastify-cookie`
- `fastify-cors`
- `fastify-static`
- `jsonwebtoken`
- `mongodb`
- `nodemailer`

## MongoDB

The application uses a free MongoDB Atlas account for its database.
There are two collections, "user" and "session".

To see the contents of these collections and delete documents from them
for retrying various scenarios, download MongoDB Compass from
<https://www.mongodb.com/products/compass>.
This provides a GUI app for interacting with MongoDB databases.
An issue with this tool is that it is often very slow to show updates
even when it is manually refreshed.

## Email

When a new account is created,
an email message is sent to the user
that contains a link they can click to verify
the email address of their account.
REST services could use the `verified` flag stored in user records
to restrict usage to verified accounts.

If a user forgets their password,
they can enter their email address in the "Forgot Password" section of the UI
and press the "Forgot Password" button.
If an account exists for that email address, an email message is sent to it
that contains a link the user can click
to browse a page that allows them to enter a new password.

In both cases the link in the email expires after 10 minutes.

The link contains either query parameters or path parameters that include
the user email address, the timestamp at which the link expires,
and one-way hash of a token that encodes the same data.
The link to reset a forgotten password uses query parameters
because it is a link to the HTML page where the user can enter a new password.
Path parameters would not work in this case.
The link to verify a new account uses path parameters
which works because it invokes a REST service.

When the server processes a click on the links described above,
it recreates the token from the non-token query parameters
and verifies that it matches the token.
This prevents tampering with the non-token query parameter values.
The hashed token value includes the value of the environment variable
`JWT_SIGNATURE` that is defined in `api/.env`.
This makes it extremely difficult for a hacker to
modify the query/path parameters in a compatible way.

The app sends email messages using a Gmail account
created specifically for this purpose.
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

## Environment variables

The app requires several environment variables
to be defined in the file `api/.env`.
This file is not in the GitHub repository.
Here is the content of that file with the values removed:

```text
# This file should be listed in .gitignore so it is not committed to the repo!

COOKIE_SIGNATURE=some-random-string

GMAIL_USER=some-name@gmail.com
GMAIL_PASS=some-password

JWT_SIGNATURE=some-random-string

MONGO_DB_NAME=test

# Replace all the values here that begin with "mongodb-atlas-".
MONGO_URL=mongodb+srv://{mongodb-atlas-username}:{mongodb-atlas-password}@{mongodb-atlas-cluster}.mongodb.net/mongodb-atlas-db-name?retryWrites=true&w=majority

ROOT_DOMAIN=nodeauth.dev
```

## HTTPS

This app requires the use of HTTPS.
This section describes steps that can be taken to configure and use this.

In macOS, edit the "hosts" file by entering `sudo vim /etc/hosts`.
Then add the following lines:

```text
127.0.0.1 nodeauth.dev
127.0.0.1 api.nodeauth.dev
```

Caddy is a local server that is implemented in Go and supports HTTPS.
Browse {% aTargetBlank "https://caddyserver.com", "caddyserver.com" %}
for installation instructions.
In macOS this can be installed by installing Homebrew
and entering `brew install caddy` and `brew install nss`.
Create the file `Caddyfile` in the project root directory
containing the following:

```text
{
  http_port 81
  local_certs
}

# This is for the UI server.
nodeauth.dev {
  reverse_proxy 127.0.0.1:5000
}

# This is for the API server.
# Why is it important for this to be a subdomain of the UI server?
api.nodeauth.dev {
  reverse_proxy 127.0.0.1:1919
}
```

To start the Caddy server, cd to the project root directory and
enter `caddy run` to run in the foreground
or `caddy start` to run in the background.
If this fails, kill the process listening on port 2019 and try again.

To stop the Caddy server, press ctrl-c or
enter `caddy stop` in another terminal window.

To reload changes to `Caddyfile` in a running server,
enter `caddy reload` in another terminal window.

## Steps to build and run the app

To build and start the API server which listens on port 1919:

- `cd api`
- `npm install`
- `npm start`

To start the Caddy server which provides support for using HTTPS:

- cd to the root project directory
- `caddy start`

If the Caddy server was running previously,
you may need to kill a process that is listening on port 2019
in order to restart Caddy.

API requests are sent to `https://api.nodeauth.dev`.

To start the UI server which listens on port 5000:

- `cd ui`
- `npm start`
- browse nodeauth.dev, NOT localhost:5000!

## Steps to exercise the app

The web UI displays a set of forms separated by horizontal lines.
Each form performs a specific task indicated by the heading above each form.

In the "Register" section, register a new account by supplying
an email address, a role, and
matching values for "Password" and "Confirm Password".
Then press the "Register" button.
This creates a new user account and logs in.

To change a password, first login.
In the "Change Password" section, supply
an email address, the current password, and the new password.
Then press the "Change Password" button.

To reset a forgotten password,
go to the "Forgot Password" section, supply an email address,
and press the "Forgot Password" button.
This sends an email containing a "Reset Password" link.
Click the link to go to a page where you can enter a new password.

Two-factor authentication requires use of a mobile authenticator app
like "Google Authenticator", so install one of these apps on your phone
if you do not already have one.
To enable two-factor authentication, first login.
Then click the link in the "Enable Two-factor Authentication" section
and follow the instructions that are displayed.
After enabling this, subsequent logins
with the email address of the current user will require
an email address, a password, and a code from the authenticator app.

To unregister the account of the currently logged in user,
press the "Unregister" button in the "Unregister" section.

If the logged in user has the "admin" role,
you can delete all the sessions of a user with a given email address
by going to the "Delete User Session" section, entering the email address,
and pressing the "Delete User Sessions" button.

If the logged in user has the "admin" role,
you can delete all the user with a given email address and all their sessions
by going to the "Delete User" section, entering the email address,
and pressing the "Delete User" button.

Clicking the "Unprotected Page" link at the bottom
will display "This is unprotected data." for any user.
It will even work if no user is logged in.
However, the "Protected Page" link at the bottom
will only be displayed if a user is logged in.
Clicking the link will display "This is protected data".
If you attempt browse the URL <https://nodeauth.dev/protected.html>
and are not logged in, you will see "Access to protected data was blocked."

## Implementation details

All the user interface code is in the "ui" directory
and is implemented using vanilla JavaScript.

All the server code is in the "api" directory.
It is implemented in Node.js and uses the
[fastify](https://github.com/fastify/fastify) library.

The UI makes REST calls using functions defined in `ui/public/fetch-util.js`
which uses the Fetch API.

The UI functionality is defined in `ui/public/ui.js`.
The functions defined in this file are fairly well-commented
and should be easy to understand.

The function assigned to `window.onload` near the bottom
associates a function with each `form` element
that is called when the form is submitted.

The UI sections that are display vary based on
whether a user is currently logged in.
The function `setLoggedIn` manages this.

UI styling is done with vanilla CSS defined in `ui/public/styles.css`.

## Passwords

The database does not store passwords in plain text.
Instead it salts and hashes passwords using the npm package
{% aTargetBlank "https://github.com/kelektiv/node.bcrypt.js", "bcrypt" %}.

The bcrypt `genSalt` function returns a `Promise`
that resolves to the salt value that is 29 characters long.
A different salt value is used for each user.
The `genSalt` function defaults to using 10 "rounds".
The number of rounds affects how long it takes to compute a salt value.

The bcrypt `hash` function takes a password and a salt value,
and returns a `Promise` that resolves to a hashed value.
This hashed value is stored as the password in the database.

During a login attempt, the bcrypt `compare` function
is used to compare the password passed in over HTTPS
to the hashed value retrieved from the database.

## Cookies

When a user successfully logs in, a new session is created
by calling the `createSession` function in `api/api.js`.
This creates a session token that is just a random string of 50 bytes.
A document containing the session token is
inserted in the MongoDB `session` collection.
Finally, the `createTokens` function is called.
This creates access and refresh tokens that are JSON Web Tokens (JWTs).

The access token contains the user id and the session token.
It expires in one minute for demo purposes addressed later.
REST services can decode the access token to get the user id
and then query the MongoDB `user` collection
to get information about the current user.

The refresh token contains the same session token.
It expires in one week.
This token is required to exist in order to create new tokens
REST calls are made after the access token has expired.

Many REST services validate that they are being called from an active session.
They do this by calling the `getUser` function in `api/api.js`.
This verifies that the request contains a valid access token.
If the access token has expired and is therefore not passed in the request,
the next step is to verify that the request contains a valid refresh token.
If it does then the refresh token is decoded to obtain the session id.
If a corresponding document exists in the MongoDB `session` collection
and the MongoDB `user` collection contains a document
corresponding to the user id associated with the session
then new access and refresh tokens are created
and the REST call proceeds.
If any of these requirements are not met,
the `getUser` function throws an error and
normal processing of the REST call does not occur.

The short lifetime for the access token was selected
in order to easily demonstrate recreating the tokens
when it expires.

These cookies are configured to be HttpOnly and Secure.
Making them HttpOnly prevents them from
being accessed using the `Document.cookie` function
which prevents them from being accessed by browser extensions.
Making them Secure requires use of HTTPS in order to
pass them between the browser and server.

## Feature Flow Summaries

### Register user

- `ui/public/index.html` renders a form with the id "register".
- `ui/public/ui.js` defines the `register` function
  which sends a POST request to the `/user` endpoint.
- `api/server.js` associates the endpoint with the `createUser` function.
- `api/api.js` defines the `createUser` function which
  inserts a document in the MongoDB `user` collection,
  automatically logs in, and
  sends an email containing a link to click to verify the account.

### Enable two-factor authentication

- `ui/public/index.html` renders a form with the id "enable-2fa".
- `ui/public/2fa.html` renders a QR code and a form for entering a code.
- `ui/public/2fa.js` defines the `setup` function which
  uses the npm libraries qrcode and @otplib/preset-browser
  to display a QR code that uses can scan with their phone camera
  to create a new entry in their mobile authenticator app.
- The code from the authenticator app is entered in the UI.
- Submitting the form this form invokes the `register2FA` function
  defined in `ui/public/2fa.js` which sends a
  POST request to the `/2fa/register` endpoint.
- `api/server.js` associates the endpoint with the `register2FA` function.
- `api/api.js` defines the `register2FA` function which
  updates a document in the MongoDB `user` collection.

### Login

- `ui/public/index.html` renders a form with the id "login".
- `ui/public/ui.js` defines the `login` function
  which sends a POST request to the `/login` endpoint.
- `api/server.js` associates the endpoint with the `login` function.
- `api/api.js` defines the `login` function which verifies the user.
  If two-factor authentication if enabled,
  that is communicated to the UI so it can prompt for a code.
  Otherwise it creates a document in the MongoDB `session` collection.

### Login with 2FA

- `ui/public/index.html` renders a form with the id "login-2fa".
- `ui/public/ui.js` defines the `login2FA` function
  which sends a POST request to the `/2fa/login` endpoint.
- `api/server.js` associates the endpoint with the `login2FA` function.
- `api/api.js` defines the `login2FA` function which
  verifies the user and the two-factor authentication code.
  If successful, it creates a document in the MongoDB `session` collection.

### Logout

- `ui/public/index.html` renders a form with the id "logout".
- `ui/public/ui.js` defines the `logout` function
  which sends a GET request to the `/logout` endpoint.
- `api/server.js` associates the endpoint with the `logout` function.
- `api/api.js` defines the `logout` function which
  deletes the associated session and clears the access and refresh tokens.

### Forgot password

- `ui/public/index.html` renders a form with the id "forgot-password".
- `ui/public/ui.js` defines the `forgotPassword` function
  which sends a GET request to the `/user/forgot-password` endpoint.
- `api/server.js` associates the endpoint with the `forgotPassword` function.
- `api/api.js` defines the `forgotPassword` function which
  triggers sending of an email that includes a link that
  can be clicked which renders `ui/public/password-reset.html`.
- `ui/public/password-reset.html` uses `ui/public/password-reset.js`
  which defines a `resetPassword` function
  that sends a POST request to the `/user/reset` endpoint.
- `api/server.js` associates the endpoint with the `resetPassword` function.
- `api/api.js` defines the `resetPassword` function which
  validates a token passed to it and
  updates a document in the MongoDB `user` collection
  with a new hashed password.

### Change password

- `ui/public/index.html` renders a form with the id "change-password".
- `ui/public/ui.js` defines the `changePassword` function
  which sends a POST request to the `/user/password` endpoint.
- `api/server.js` associates the endpoint with the `changePassword` function.
- `api/api.js` defines the `changePassword` function which
  verifies the user and updates a document in the MongoDB `user` collection.

### Unregister user

- `ui/public/index.html` renders a form with the id "unregister".
- `ui/public/ui.js` defines the `unregister` function
  which sends a DELETE request to the `/user` endpoint.
- `api/server.js` associates the endpoint with the `deleteCurrentUser` function.
- `api/api.js` defines the `deleteCurrentUser` function which
  verifies the user and deletes a document from the MongoDB `user` collection.

### Delete sessions

- `ui/public/index.html` renders a form with the id "delete-user-sessions".
- `ui/public/ui.js` defines the `deleteUserSessions` function
  which sends a DELETE request to the `/user/{email}/sessions` endpoint.
- `api/server.js` associates the endpoint with the `deleteUserSessions` function.
- `api/api.js` defines the `deleteUserSessions` function which
  verifies the current user,
  including verifying that they have the "admin" role,
  and deletes documents associated with the given email address
  from the MongoDB `session` collection.

### Delete user

- `ui/public/index.html` renders a form with the id "delete-user".
- `ui/public/ui.js` defines the `deleteUser` function
  which sends a DELETE request to the `/user/{email}` endpoint.
- `api/server.js` associates the endpoint with the `deleteUser` function.
- `api/api.js` defines the `deleteUser` function which
  verifies the current user,
  including verifying that they have the "admin" role,
  deletes documents associated with the given email address
  from the MongoDB `session` collection,
  and deletes a document from the MongoDB `user` collection.

### Page navigation

One reason to require users to authenticate is to have
pages that are only accessible to authenticated users.
In order to demonstrate this, the app has two pages
that are linked from the main page.

The first link is "Unprotected Page".
Clicking this navigates to a page that renders "This is unprotected data.".
It is not necessary to login in order to access this page.

The second link is "Protected Page".
This link is only rendered when a user has logged in.
Clicking this navigates to a page that renders "This is protected data."
When no user is logged in, the browser URL can be manually changed to
"https://nodeauth.dev/protected.html" to attempt to access the protected page.
But it will render "Access to protected data was blocked."
