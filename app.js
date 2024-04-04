import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import brt from "bcrypt";


const app = express();
const port = process.env.PORT || 3000;
const salt_round = 10;

const db = new pg.Client({
  user: process.env.user_db,
  host: process.env.host_db,
  database: process.env.db_pass,
  password: process.env.pg_pass,
  port: process.env.port_db,
  ssl: true
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      brt.hash(password,salt_round,async(err, hash)=>{
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2)",
          [email, hash]
        );
        console.log(result,hash);
        res.render("secrets.ejs");
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1",[email]);
    if (checkResult.rows.length > 0) {
      const user_hash = checkResult.rows[0].password;
      brt.compare(user_pass,user_hash,(err,result)=>{
        
        if (!result) {
          res.send('<h2>PASSWORD NOT MATCH,</h2><h1>try agin</h1>')
        }else{
          res.render("secrets.ejs")
        }
      })
    }else{
      res.send(`<h1>${email} = 'NOT FOUND'</h1>`)
    }
  } catch (error) {
    console.log(error);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
