import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import brt from "bcrypt";

import session from "express-session";
import  Strategy  from "passport-local";
import passport from "passport";


const app = express();
const port = process.env.PORT || 3000;
const salt_round = 10;

const db = new pg.Client({
  user: process.env.user,
  host: process.env.host,
  database: process.env.database,
  password: process.env.password,
  port_DB: process.env.port_DB,
  ssl: true
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
//allow create session id
app.use(session({
  secret:"TOPSECRET",
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

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users_login WHERE email_address = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      brt.hash(password,salt_round,async(err, hash)=>{
        const result = await db.query(
          "INSERT INTO users_login (email_address, password) VALUES ($1, $2) RETURNING *",
          [email, hash]
        );
        // console.log(result);
        const user = result.rows[0];
        req.login(user,(err) =>{
          console.error(err);
          res.redirect("/secrets");
        })
      });
    }
  } catch (err) {
    console.log(err);
  }
});


app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

//verify user
passport.use(new Strategy(async function verify(username,password,cd){
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
