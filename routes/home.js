import express from "express";
const router = express.Router();

// Home route
router.get("/", (req, res) => {
  res.render("home.ejs");
});

export default router;
