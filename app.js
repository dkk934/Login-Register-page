// Load environment variables from .env file
import dotenv from "dotenv";
dotenv.config();

import express, { request } from "express";
import bodyParser from "body-parser";
import pg from "pg";
import brt from "bcrypt"; // Import bcrypt for hashing passwords

import session from "express-session"; // Import express-session for session management
import Strategy from "passport-local"; // Import local strategy for username/password authentication
import passport from "passport"; // Import passport for authentication
import GoogleStrategy from "passport-google-oauth2"; // Import Google OAuth2 strategy for Google login

const app = express();
const port = process.env.PORT || 3000; // Set port from environment variable or default to 3000
const salt_round = 10; // Number of salt rounds for bcrypt hashing

// Configure PostgreSQL client with connection details from environment variables
const db = new pg.Client({
  user: process.env.user,
  host: process.env.host,
  database: process.env.database,
  password: process.env.password,
  port_DB: process.env.port_DB,
  // ssl: true // Uncomment if SSL is required for the database connection
});

db.connect(); // Connect to the PostgreSQL database

app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static("public")); // Serve static files from the "public" directory

// Configure session management
app.use(session({
  secret: process.env.SESSION_SECRET, // Use a secret key from environment variables
  resave: false, // Don't save session if it hasn't been modified
  saveUninitialized: true, // Save uninitialized sessions
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // Set session cookie to expire after 24 hours
  }
}));

app.use(passport.initialize()); // Initialize Passport for authentication
app.use(passport.session()); // Enable session support for Passport

// Home route
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// Login route
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// Register route
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Secret route, accessible only if authenticated
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/");
  }
});

// Google OAuth authentication route
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], // Request user's profile and email from Google
  })
);

// Google OAuth callback route
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets", // Redirect to secrets page on successful login
    failureRedirect: "/login", // Redirect to login page on failure
  })
);

// Local login route using Passport's local strategy
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets", // Redirect to secrets page on successful login
    failureRedirect: "/login", // Redirect to login page on failure
  })
);

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err); // Handle error during logout
    }
    res.redirect("/"); // Redirect to home page after logout
  });
});

// Registration route
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users_login WHERE email_address = $1", [email]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login"); // Redirect to login if user already exists
    } else {
      // Hash the password using bcrypt before storing in the database
      brt.hash(password, salt_round, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          // Insert new user into the database
          const result = await db.query(
            "INSERT INTO users_login (email_address, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          // Automatically log in the user after successful registration
          req.login(user, (err) => {
            console.log("Registration successful");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err); // Log any errors
  }
});

// Passport local strategy for verifying username and password
passport.use("local",
  new Strategy(async function verify(username, password, done) {
    try {
      const checkResult = await db.query("SELECT * FROM users_login WHERE email_address = $1", [username]);
      if (checkResult.rows.length > 0) {
        const user = checkResult.rows[0];
        const hash = user.password;
        // Compare the provided password with the stored hash
        brt.compare(password, hash, (err, result) => {
          if (err) {
            return done(err, "Error comparing password:");
          } else {
            if (!result) {
              return done(null, false); // Password incorrect
            } else {
              return done(false, user); // Password correct, return user object
            }
          }
        });
      } else {
        return done("User not found"); // User does not exist in database
      }
    } catch (error) {
      return done(error); // Handle any other errors
    }
  })
);

// Google OAuth strategy for Google login
passport.use(
  "google",
  new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID, // Google client ID from environment variables
    clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Google client secret from environment variables
    callbackURL: "http://localhost:3000/auth/google/secrets", // Redirect URL after Google login
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", // Access Google API for user info
  },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile.email); // Log the email from the Google profile
        const result = await db.query("SELECT * FROM users_login WHERE email_address = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          // If user doesn't exist, create a new user with a "google" password
          const newUser = await db.query(
            "INSERT INTO users_login (email_address, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]); // If user exists, return the user object
        }
      } catch (err) {
        return cb(err); // Handle any errors
      }
    }
  )
);

// Store user information in session
passport.serializeUser((user, done) => {
  console.log(user);
  
  done(null, user); // Serialize the entire user object into the session
});

// Retrieve user information from session
passport.deserializeUser((user, done) => {
  done(null, user); // Deserialize the user object from the session
});

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});
