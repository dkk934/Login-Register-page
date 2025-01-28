import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const db = new pg.Client({
  user: process.env.user,
  host: process.env.host,
  database: process.env.database,
  password: process.env.password,
  port: process.env.port_DB,
});

db.connect();

export default db;
