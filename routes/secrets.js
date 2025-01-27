import express from "express";

const router = express.Router();

// Protected secrets route
router.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/");
  }
});

export default router;
