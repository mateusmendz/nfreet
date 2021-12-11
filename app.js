var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var mongoose = require("mongoose");
require("./models");
var bcrypt = require("bcrypt");
var expressSession = require("express-session");
var passport = require("passport");
var LocalStrategy = require("passport-local").Strategy;
var dotenv = require("dotenv");
dotenv.config();
var User = mongoose.model("User");

mongoose.connect("mongodb://" process.env.MONGO_USERNAME + ":" + process.env.MONGO_PASSWORD + "@localhost:27017/nfreetdb");

var app = express();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  expressSession({
    secret: process.env.EXPRESS_SESSION_SECRET,
  })
);
app.use(passport.initialize());
app.use(passport.session());
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (email, password, next) {
      User.findOne(
        {
          email: email,
        },
        function (err, user) {
          if (err) return next(err);
          if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
            return next({ message: "Email ou senha incorretos" });
          }
          next(null, user);
        }
      );
    }
  )
);

passport.use(
  "signup-local",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (email, password, next) {
      User.findOne(
        {
          email: email,
        },
        function (err, user) {
          if (err) return next(err);
          if (user) return next({ message: "Usuário já registrado" });
          let newUser = new User({
            email: email,
            passwordHash: bcrypt.hashSync(password, 10),
          });
          newUser.save(function (err) {
            next(err, newUser);
          });
        }
      );
    }
  )
);

passport.serializeUser(function (user, next) {
  next(null, user._id);
});
passport.deserializeUser(function (id, next) {
  User.findById(id, function (err, user) {
    next(err, user);
  });
});

app.get("/", function (req, res, next) {
  res.render("index");
});

app.get("/login", function (req, res, next) {
  res.render("login");
});

app.get("/register", function (req, res, next) {
  res.render("register");
});

app.get("/create", function (req, res, next) {
  res.render("create");
});

app.post(
  "/signin",
  passport.authenticate("local", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/");
  }
);

app.post(
  "/signup",
  passport.authenticate("signup-local", { failureRedirect: "/register" }),
  function (req, res) {
    res.redirect("/");
  }
);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

module.exports = app;
