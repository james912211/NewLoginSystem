const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const app = express();
const pool = require("./models/user_model"); // 引用 MySQL 連線
const authRoutes = require("./routes/auth_routes");
const profileRoutes = require("./routes/profile_routes");
require("./config/passport");
const passport = require("passport");
const session = require("express-session");
const flash = require("connect-flash");

//設定middleware跟排版引擎
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});

app.use("/auth", authRoutes);
app.use("/profile", profileRoutes);

app.get("/", (req, res) => {
  return res.render("index", { user: req.user });
});

app.listen(8080, () => {
  console.log("Server running on port 8080。。。。");
});
