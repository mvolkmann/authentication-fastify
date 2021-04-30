# authentication-fastify

## Overview

This application demonstrates user management using Node.js and Fastify.
It is based on ideas from the Level Up Tutorials courses
"Node Fundamentals Authentication" and "Level 2 Node Authentication".
It is useful for learning about patterns in user management
that are not tied to a specific server side programming language
or collection of libraries.
Languages other that JavaScript likely have similar libraries
that can be used to implement the same functionality.

The web UI uses vanilla JavaScript instead of a framework
in order to avoid appealing to users of a particular framework
and to keep the UI simple.

## MongoDB

The application uses a free MongoDB Atlas account for its database.
There are two collections, "user" and "session".
To see the contents of these collections and delete documents from them
for retrying various scenarios, download MongoDB Compass from
<https://www.mongodb.com/products/compass>.
This provides a GUI app for interacting with MongoDB databases.

## Email

The app sends email using a Gmail account
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
MONGO_URL=mongodb+srv://mongodb-atlas-username:mongodb-atlas-password@mongodb-atlas-cluster.mongodb.net/mongodb-atlas-db-name?retryWrites=true&w=majority

ROOT_DOMAIN=nodeauth.dev
```

## Steps to build and run the app

To build and start the API server which listens on port 1919:

- `cd api`
- `npm install`
- `npm start`

To start the Caddy server which provides support for using HTTPS:

- cd to the root project directory
- `caddy start`

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

## UI implementation details

All the user interface code is in the "ui" directory
and is implemented using vanilla JavaScript.

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

## Server implementation details

All the server code is in the "api" directory.
