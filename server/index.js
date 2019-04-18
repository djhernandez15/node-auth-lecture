require("dotenv").config();
const express = require("express");
const app = express();
const session = require("express-session");
const massive = require("massive");
const bcrypt = require("bcryptjs");

massive(process.env.CONNECTION_STRING).then(db => {
  app.set("db", db);
  console.log("Database connected");
  if (!db.auth_user) {
    db.initialSetup().then(result => console.log("Table created"));
  }
});

app.use(
  session({ secret: "househunters", resave: false, saveUninitialized: true })
);

app.use(express.json());

app.get("/auth/me", (req, res) => {
  res.json(req.session.user);
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await req.app.get("db").getUser(username);
  if (result.length > 0) {
    //we need to check password
    const isMatch = await bcrypt.compare(password, result[0].password);
    if (isMatch) {
      req.session.user = result[0].username;
      res.json(username);
    } else {
      res.status(403).json("Incorrect username or password");
    }
  } else {
    res.status(403).json("Incorrect username or password");
  }
});

app.post("/auth/signup", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10).catch(err => console.log(err));
  const dbResult = await req.app
    .get("db")
    .addUser([username, hash])
    .catch(err => console.log(err));
  req.session.user = username;
  res.json(dbResult);
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy();
  res.json("Successfully logged out!");
});

app.listen(5050, () => console.log("Listening on 5050"));
