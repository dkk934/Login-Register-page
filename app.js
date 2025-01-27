import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import dotenv from "dotenv";
import passport from "./config/passport.js";
import homeRoutes from "./routes/home.js";
import authRoutes from "./routes/auth.js";
import secretRoutes from "./routes/secrets.js";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Use routes
app.use("/", homeRoutes);
app.use("/", authRoutes);
app.use("/", secretRoutes);

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
