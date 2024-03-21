const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const pool = require("../models/user_model"); // 引用 MySQL 連線
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");
const LineStrategy = require("passport-line");

passport.serializeUser((user, done) => {
  console.log("Serialize使用者。。。");
  //   console.log(user.id);
  done(null, user.id); //資料庫的id，存在session，並將id簽名後以cookie形式傳給使用者
});

passport.deserializeUser(async (id, done) => {
  console.log(
    "Deserialize使用者。。。使用serializeUser儲存的id，去找到資料庫內的資料"
  );
  //   console.log(id);
  let [foundUser] = await pool.query("SELECT * FROM users WHERE id = ?", [id]);
  //   console.log(foundUser);
  done(null, foundUser); //將req.user這個屬性設為foundUser
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:8080/auth/google/redirect",
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("進入Google strategy的區域");
      //先拿到使用者的email
      const email = profile.emails[0].value;
      //查資料庫使用者的email是否存在
      const [existingUser] = await pool.query(
        "SELECT * FROM users WHERE email = ?",
        [email]
      );
      if (existingUser) {
        //使用者存在
        console.log("使用者已存在");
        done(null, existingUser);
      } else {
        // 使用者不存在，將其資料插入到資料庫中
        await pool.query(
          "INSERT INTO users (name,googleID,thumbnail,email) VALUES(?,?,?,?)",
          [
            profile.displayName,
            profile.id,
            profile.photos[0].value,
            profile.emails[0].value,
          ]
        );
        // 再次查詢以獲取新加入的使用者
        const [newUser] = await pool.query(
          "SELECT * FROM users WHERE email = ?",
          [email]
        );
        console.log("新使用者已創建");
        done(null, newUser);
      }
    }
  )
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    let [foundUser] = await pool.query("SELECT * FROM users WHERE email = ?", [
      username,
    ]);
    if (foundUser) {
      let result = await bcrypt.compare(password, foundUser.password);
      if (result) {
        done(null, foundUser);
      } else {
        done(null, false);
      }
    } else {
      done(null, false);
    }
  })
);

passport.use(
  new LineStrategy(
    {
      channelID: process.env.LINE_CHANNEL_ID,
      channelSecret: process.env.LINE_CHANNEL_SECRET,
      callbackURL: "http://localhost:8080/auth/line/redirect",
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("進入LineStrategy區域。。。");
      const id = profile.id;
      const [existingUser] = await pool.query(
        "SELECT * FROM users WHERE lineID = ?",
        [id]
      );
      if (existingUser) {
        //使用者存在
        console.log("使用者已存在");
        done(null, existingUser);
      } else {
        // 使用者不存在，將其資料插入到資料庫中
        await pool.query(
          "INSERT INTO users (name,lineID,thumbnail) VALUES(?,?,?)",
          [profile.displayName, profile.id, profile.pictureUrl]
        );
        // 再次查詢以獲取新加入的使用者
        const [newUser] = await pool.query(
          "SELECT * FROM users WHERE lineID = ?",
          [id]
        );
        console.log("新使用者已創建");
        done(null, newUser);
      }
    }
  )
);
