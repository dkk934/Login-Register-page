import dotenv from "dotenv";
dotenv.config();
import express, { request } from "express";
import bodyParser from "body-parser";
import pg from "pg";
import brt from "bcrypt";

import session from "express-session";
import  Strategy  from "passport-local";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = process.env.PORT || 3000;
const salt_round = 10;

const db = new pg.Client({
  user: process.env.user,
  host: process.env.host,
  database: process.env.database,
  password: process.env.password,
  port_DB: process.env.port_DB,
  // ssl: true
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
//allow create session id
app.use(session({
  secret:process.env.eny_key,
  resave: false,
  saveUninitialized:true,
  cookie:{
    maxAge: 1000 * 60 * 60 * 24 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//direct route to secretes if Authenticated
app.get("/secrets",(req,res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/");
  }
})

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
   passport.authenticate("local",{
    successRedirect: "/secrets",
    failureRedirect: "/login"
})
);


app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users_login WHERE email_address = $1", [email]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      brt.hash(password,salt_round,async(err, hash)=>{
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users_login (email_address, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
        // console.log(result);
        const user = result.rows[0];
        req.login(user, (err) => {
          console.log("success");
          res.redirect("/secrets");
        });
      }
    });
  }
} catch (err) {
  console.log(err);
}
});



//verify user
passport.use("local",
  new Strategy(async function verify(username,password,cd){
  try { 
    const checkResult = await db.query("SELECT * FROM users_login WHERE email_address = $1",[username]);
    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const hash = user.password;
      brt.compare(password,hash,(err,result)=>{
        if (err) {
          return cd(err,"Error comparing password:");
        } else {
          if (!result) {
            return cd(null,false);
          }else{
            // console.log(result);
            return cd(false,user);
          }
        }
      });
    }else{
      return cd("user not found")
    }
  } catch (error) {
    return cd(error);
  }
}))

//google oauth
passport.use(
  "google",
  new GoogleStrategy({
  clientID: process.env.client_id,
  clientSecret: process.env.client_secret,
  callbackURL:"http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", //access google api for user info
},
async (accessToken, refreshToken, profile, cb)=> {
    try {
      console.log(profile.email);
      const result = await db.query("SELECT * FROM users_login WHERE email_address = $1", [
        profile.email,
      ]);
      if (result.rows.length === 0) {
        const newUser = await db.query(
          "INSERT INTO users_login (email_address, password) VALUES ($1, $2)",
          [profile.email, "google"]
        );
        return cb(null, newUser.rows[0]);
      } else {
        return cb(null, result.rows[0]);
      }
    } catch (err) {
      return cb(err);
    }
}
));

//store user info 
passport.serializeUser((user,cd) =>{
  cd(null,user);
})

passport.deserializeUser((user,cd) =>{
  cd(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});
