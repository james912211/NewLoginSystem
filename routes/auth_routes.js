const router = require("express").Router();
const passport = require("passport");
const pool = require("../models/user_model");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

//http://localhost:8080/auth/login
router.get("/login", (req, res) => {
  return res.render("login", { user: req.user });
});

//點選登出，會清空session
router.get("/logout", (req, res) => {
  req.logOut((err) => {
    if (err) return res.send(err);
    return res.redirect("/");
  });
});
//http://localhost:8080/auth/signup
router.get("/signup", (req, res) => {
  return res.render("signup", { user: req.user });
});

router.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/auth/login",
    failureFlash: "帳號或密碼錯誤",
  }),
  (req, res) => {
    return res.redirect("/profile");
  }
);

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], //要什麼資料
    prompt: "select_account", //可以有選擇帳號的頁面
  })
);

router.get(
  "/line",
  passport.authenticate("line", {
    scope: ["profile"],
  })
);

router.post("/signup", async (req, res) => {
  let { name, email, password } = req.body;
  // console.log(name, email, password);
  if (password.length < 8) {
    req.flash("error_msg", "密碼長度過短，至少需要8個數字或英文字。");
    return res.redirect("/auth/signup");
  }

  //確認信箱有沒有被註冊過
  const [foundEmail] = await pool.query("SELECT * FROM users WHERE email = ?", [
    email,
  ]);
  if (foundEmail) {
    req.flash("error_msg", "信箱已被註冊，請使用另一個信箱");
    return res.redirect("/auth/signup");
  }

  let hashedPassword = await bcrypt.hash(password, 12);
  await pool.query("INSERT INTO users (name,email,password) VALUES(?,?,?)", [
    name,
    email,
    hashedPassword,
  ]);
  req.flash("success_msg", "註冊會員成功，現在可以登入了");
  return res.redirect("/auth/login");
});

router.get("/google/redirect", passport.authenticate("google"), (req, res) => {
  return res.redirect("/profile");
});

router.get("/line/redirect", passport.authenticate("line"), (req, res) => {
  return res.redirect("/profile");
});

router.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { user: req.user });
});

// 建立一個 Nodemailer 的 Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "jqchan136309@gmail.com", // 你的 Gmail 用戶名
    pass: "wzncxuixzselvefp", // 你的 Gmail 密碼
  },
});

// 處理忘記密碼請求
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [
    email,
  ]);
  if (!user) {
    req.flash("error_msg", "該電子郵件地址尚未註冊");
    return res.redirect("/auth/forgot-password");
  }

  // 生成重設密碼令牌並存儲到資料庫中
  const token = crypto.randomBytes(20).toString("hex");
  await pool.query("UPDATE users SET reset_token = ? WHERE email = ?", [
    token,
    email,
  ]);

  // 發送包含重設密碼連結的郵件給使用者
  const resetLink = `${req.protocol}://${req.get(
    "host"
  )}/auth/reset-password?token=${token}`;

  // 使用 Nodemailer 發送郵件
  transporter.sendMail(
    {
      from: "jqchan136309@gmail.com", // 你的 Gmail 用戶名
      to: email, // 使用者的電子郵件地址
      subject: "重設密碼",
      text: `您的重設密碼連結：${resetLink}`,
    },
    (error, info) => {
      if (error) {
        console.error("郵件發送失敗：", error);
      } else {
        console.log("郵件已成功發送：", info.response);
      }
    }
  );

  req.flash("success_msg", "請檢查您的電子郵件以重設密碼");
  res.redirect("/auth/login");
});

router.get("/reset-password", async (req, res) => {
  const { token } = req.query;
  // console.log(token);
  const result = await pool.query("SELECT * FROM users WHERE reset_token = ?", [
    token,
  ]);
  const users = result[0];

  if (users.length === 0) {
    req.flash("error_msg", "無效的重設密碼連結");
    return res.redirect("/auth/login");
  }

  // 渲染用戶重設密碼的頁面，允許用戶輸入新密碼
  res.render("reset-password", { token, user: users });
});

router.post("/reset-password", async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;

  try {
    if (newPassword !== confirmPassword) {
      req.flash("error_msg", "新密碼和確認密碼不一致");
      return res.redirect(`/auth/reset-password?token=${token}`);
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE reset_token = ?",
      [token]
    );
    const users = result[0]; // 查詢結果應該是result的第一個元素
    console.log(users);
    if (!users || users.length === 0) {
      // 確保users存在且不是空陣列
      req.flash("error_msg", "無效的重設密碼連結");
      return res.redirect("/auth/login");
    }

    const user = users; // 獲取用戶對象

    // 更新用戶的密碼為新密碼
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query(
      "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
      [hashedPassword, user.id]
    );

    req.flash("success_msg", "密碼重設成功，請使用新密碼登入");
    res.redirect("/auth/login");
  } catch (error) {
    console.error("處理重設密碼請求時發生錯誤：", error);
    req.flash("error_msg", "密碼重設失敗");
    res.redirect("/auth/login");
  }
});

// 重設密碼
router.get("/change-password", (req, res) => {
  // 確保用戶已經登入
  if (!req.isAuthenticated()) {
    req.flash("error_msg", "請先登入");
    return res.redirect("/auth/login");
  }
  return res.render("change-password", { user: req.user });
});

// 處理更改密碼的請求
router.post("/change-password", async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  // 確保用戶已經登入
  if (!req.isAuthenticated()) {
    req.flash("error_msg", "請先登入");
    return res.redirect("/auth/login");
  }

  const user = req.user; // 通過 Passport 獲得當前登入的用戶
  console.log(oldPassword, newPassword, confirmPassword);
  // 檢查舊密碼是否正確
  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    req.flash("error_msg", "舊密碼錯誤");
    return res.redirect("/auth/change-password");
  }

  // 確認新密碼和確認密碼是否一致
  if (newPassword !== confirmPassword) {
    req.flash("error_msg", "新密碼和確認密碼不匹配");
    return res.redirect("/auth/change-password");
  }

  // 更新密碼
  const hashedPassword = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password = ? WHERE id = ?", [
    hashedPassword,
    user.id,
  ]);

  req.flash("success_msg", "密碼更改成功，3秒後將跳回個人頁面");
  res.redirect("/auth/change-password");
});
module.exports = router;
