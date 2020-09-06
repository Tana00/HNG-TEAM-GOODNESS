const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const db = require("./config/config").get(process.env.NODE_ENV);
const User = require("./models/user");
const { auth } = require("./middlewares/auth");

const authApp = express();

// app use
authApp.use(bodyParser.urlencoded({ extended: false }));
authApp.use(bodyParser.json());
authApp.use(cookieParser());

// database connection
mongoose.Promise = global.Promise;
mongoose.connect(
  db.DATABASE,
  { useNewUrlParser: true, useUnifiedTopology: true },
  (err) => {
    if (err) console.log(err);
    console.log("database is connected");
  }
);

authApp.get("/", (req, res) => {
  res.status().send(`Welcome to login, sign-up api`);
});

//adding new user (sign-up, route)
authApp.post("/api/register", (req, res) => {
  //taking a new user
  const newUser = new User(req.body);

  if (newUser.password != newUser.password2)
    return res.status(400).json({ message: "passwords do not match" });

  User.findOne({ email: newUser.email }, (err, user) => {
    if (user)
      return res
        .status(400)
        .json({ auth: false, message: "email already exist" });

    newUser.save((err, doc) => {
      if (err) {
        console.log(err);
        return res.status(400).json({ success: false });
      }
      res.status(200).json({
        success: true,
        user: doc,
      });
    });
  });
});

// login user
authApp.post("/api/login", (req, res) => {
  let token = req.cookies.auth;
  User.findByToken(token, (err, user) => {
    if (err) return res(err);
    if (user)
      return res.status(400).json({
        error: true,
        message: "You are already logged in",
      });
    else {
      User.findOne({ email: req.body.email }, (err, user) => {
        if (!user)
          return res.json({
            isAuth: false,
            message: "Auth failed, email not found",
          });

        user.comparepassword(req.body.password, (err, isMatch) => {
          if (!isMatch)
            return res.json({ Auth: false, message: "Passwords do not match" });

          user.generateToken((err, user) => {
            if (err) return res.status(400).send(err);
            res.cookie("auth", user.token).json({
              isAuth: true,
              id: user._id,
              email: user.email,
            });
          });
        });
      });
    }
  });
});

// get logged in user
authApp.get("/api/profile", auth, (req, res) => {
  res.json({
    isAuth: true,
    id: req.user._id,
    email: req.user.email,
    name: req.user.firstname + req.user.lastname,
  });
});

// logout user
authApp.get("/api/logout", auth, (req, res) => {
  req.user.deleteToken(req.token, (err, user) => {
    if (err) return res.status(400).send(err);
    res.sendStatus(200);
  });
});

//listening port
const PORT = process.env.PORT || 5000;
authApp.listen(PORT, () => {
  console.log(`App is live at ${PORT}`);
});
