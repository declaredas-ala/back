const db = require("../models");
const jwt = require("jsonwebtoken");
const User = db.user;
const bcrypt = require("bcryptjs");
exports.allAccess = (req, res) => {
  res.status(200).send("Public Content.");
};

exports.userBoard = (req, res) => {
  res.status(200).send("User Content.");
};

exports.adminBoard = (req, res) => {
  res.status(200).send("Admin Content.");
};

exports.moderatorBoard = (req, res) => {
  res.status(200).send("Moderator Content.");
};
exports.update = (req, res) => {};

exports.updateProfile = (req, res) => {
  const userId = req.userId;

  User.findByPk(userId)
    .then((user) => {
      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      // Update user information
      user
        .update({
          username: req.body.username || user.username,
          email: req.body.email || user.email,
          password: req.body.password
            ? bcrypt.hashSync(req.body.password, 8)
            : user.password,
        })
        .then((updatedUser) => {
          res.status(200).send({
            message: "User profile updated successfully!",
            user: updatedUser,
          });
        })
        .catch((err) => {
          res.status(500).send({ message: err.message });
        });
    })
    .catch((err) => {
      res.status(500).send({ message: err.message });
    });
};
