const express = require("express");
const bcrypt = require("bcryptjs");
const Users = require("./users-model");
const restrict = require("../middleware/restrict");
const jwt = require("jsonwebtoken");

const router = express.Router();

router.get("/users", restrict("premium"), async (req, res, next) => {
  try {
    res.json(await Users.find());
  } catch (err) {
    next(err);
  }
});

router.post("/users", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await Users.findBy({ username }).first();

    if (user) {
      return res.status(409).json({
        message: "Username is already taken",
      });
    }

    const newUser = await Users.add({
      username,
      // hash the password with a time complexity of "14"
      password: await bcrypt.hash(password, 14),
    });

    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await Users.findBy({ username }).first();

    if (!user) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    // hash the password again and see if it matches what we have in the database
    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    // Generate new JSON web token
    const token = jwt.sign(
      {
        userID: user.id,
        userRole: "paid",
      },
      process.env.JWT_SECRET
    );

    // Setting up cookies
    res.cookie("token", token);

    res.json({
      message: `Welcome ${user.username}!`,
    });
  } catch (err) {
    next(err);
  }
});

router.get("/logout", async (req, res, next) => {
  try {
    // this will delete the session in the database and try to expire the cookie,
    // though it's ultimately up to the client if they delete the cookie or not.
    // but it becomes useless to them once the session is deleted server-side.
    req.session.destroy((err) => {
      if (err) {
        next(err);
      } else {
        res.status(204).end();
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
