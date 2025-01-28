import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import bcrypt from "bcrypt";
import db from "../db.js";

// Local strategy for login
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users_login WHERE email_address = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const hash = user.password;
        bcrypt.compare(password, hash, (err, isMatch) => {
          if (err) return done(err);
          if (!isMatch) return done(null, false, { message: "Invalid credentials" });
          return done(null, user);
        });
      } else {
        return done(null, false, { message: "User not found" });
      }
    } catch (error) {
      return done(error);
    }
  })
);

// Google OAuth strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await db.query("SELECT * FROM users_login WHERE email_address = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users_login (email_address, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return done(null, newUser.rows[0]);
        } else {
          return done(null, result.rows[0]);
        }
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

export default passport;
