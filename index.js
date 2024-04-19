import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

import bycrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 1 ;
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "Radha@12345",
  port: 5432,
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
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {

      bycrypt.hash(password,saltRounds,async(err,hash)=>{
        if(err){
          console.log("Error in hashing",err);
        }else{
          const result = await db.query(`INSERT INTO users(email,password) VALUES($1,$2)`,[email,hash]);
          console.log(result)
        };
        
        res.render("secrets.ejs");
      })
     
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const login_email = req.body.username;
  const login_password = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      login_email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const stored_hashed_password = user.password;
      console.log("loginpassword",login_password,stored_hashed_password)
      bycrypt.compare(login_password,stored_hashed_password,(err,isMatch)=>{
        if(err){
          console.log("Error while login ",err);
          return 
        }else{ 
          
          if(isMatch){
          res.render("secrets.ejs");
        } else {
          res.send("Incorrect Password");
        }
      }
      })
      
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
