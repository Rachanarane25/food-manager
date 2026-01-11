const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

const router = express.Router();

/* =====================
   CLIENT REGISTER
===================== */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.redirect("/register.html?error=exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword,
      role: "client"
    });

    // After successful registration → login page
    return res.redirect("/login.html");

  } catch (err) {
    console.error(err);
    return res.redirect("/register.html?error=failed");
  }
});

/* =====================
   LOGIN
===================== */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.redirect("/login.html?error=notfound");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.redirect("/login.html?error=wrong");
    }

    // Store session
    req.session.user = {
      id: user._id,
      role: user.role
    };

    // Role-based redirect
    if (user.role === "admin") {
      return res.redirect("/admin.html");
    } else {
      return res.redirect("/client.html");
    }

  } catch (err) {
    console.error(err);
    return res.redirect("/login.html?error=wrong");
  }
});

/* =====================
   LOGOUT
===================== */
router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

module.exports = router;
