import express from "express";
import passport from "passport";
import bcrypt from "bcrypt";
import db from "../db.js";

const router = express.Router();
const salt_round = 10;

// Login route
router.get("/login", (req, res) => res.render("login.ejs"));

// Register route
router.get("/register", (req, res) => res.render("register.ejs"));

// Local login
router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Google OAuth
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Registration
router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query("SELECT * FROM users_login WHERE email_address = $1", [username]);
    if (result.rows.length > 0) {
      res.redirect("/login");
    } else {
      const hash = await bcrypt.hash(password, salt_round);
      await db.query("INSERT INTO users_login (email_address, password) VALUES ($1, $2)", [username, hash]);
      res.redirect("/login");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error registering user");
  }
});

// Logout
router.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

export default router;
