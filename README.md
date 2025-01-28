# Express.js User Registration and Login

This is a simple Node.js application built with Express.js for user registration and login. It uses PostgreSQL as the database for storing user information securely.

## Features

- User registration with form validation.
- Secure user login with hashed passwords using `bcrypt`.
- Environment-based configuration for database credentials.
- Google OAuth 2.0 integration for user authentication.
- Session management with `express-session`.

## Setup and Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd Login-Register-page
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Configure the environment**:

   - Create a `.env` file in the root directory.
   - Add the following variables to match your PostgreSQL and Google OAuth setup:
     ```env
     DB_HOST=your_database_host
     DB_PORT=your_database_port
     DB_USER=your_database_user
     DB_PASSWORD=your_database_password
     DB_NAME=your_database_name

     GOOGLE_CLIENT_ID=your_google_client_id
     GOOGLE_CLIENT_SECRET=your_google_client_secret
     GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
     SESSION_SECRET=your_session_secret
     ```

4. **Run the server**:

   ```bash
   npm start
   ```

## Usage

- **Register**: Navigate to `/register` to create a new account.
- **Login**: Navigate to `/login` to sign in with existing credentials.
- **Google OAuth Login**: Navigate to `/auth/google` to sign in using Google.

## Google OAuth and Session Management

- **Google OAuth 2.0**:
  - Users can authenticate using their Google accounts.
  - After successful authentication, users are redirected to the home page or a designated route.

- **Session Management**:
  - `express-session` is used to maintain user sessions.
  - Sessions are securely stored, and a `SESSION_SECRET` is used to sign the session ID cookie.

## Dependencies

The application uses the following Node.js packages:

- `express` - Web framework for Node.js
- `dotenv` - For environment variable management
- `pg` - PostgreSQL client for Node.js
- `bcrypt` - For password hashing
- `body-parser` - Middleware for parsing incoming requests
- `passport` - Middleware for authentication
- `passport-google-oauth20` - Strategy for Google OAuth 2.0
- `express-session` - Middleware for session management

## Contributing

Contributions are welcome! If you'd like to suggest new features or report a bug, please open an issue. Pull requests are appreciated for minor changes and enhancements.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

