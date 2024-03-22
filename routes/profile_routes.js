const router = require("express").Router();

const authCheck = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    return res.redirect("/auth/login");
  }
};

router.get("/", authCheck, (req, res) => {
  console.log(req.user);
  return res.render("profile", { user: req.user });
});

router.get("/gift", authCheck, (req, res) => {
  return res.render("gift", { user: req.user });
});

router.get("/edit", authCheck, (req, res) => {
  console.log(req.user);
  return res.render("edit", { user: req.user });
});

module.exports = router;
