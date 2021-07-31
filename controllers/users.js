var async = require("async");
var nodemailer = require("nodemailer");
var crypto = require("crypto");
const User = require("../models/User");
const dotenv = require("dotenv");
dotenv.config();
var pass = process.env.USER_PASSWORD;
var emailID = process.env.USER_EMAILID;

module.exports.renderRegister = (req, res) => {
  res.render("users/register");
};

module.exports.register = async (req, res) => {
  try {
    console.log(req.body);
    const { username, email, password } = req.body;
    const user = new User({ username, email });
    const registeredUser = await User.register(user, password);
    req.login(registeredUser, (err) => {
      if (err) return next();

      res.redirect("/");
    });
  } catch (e) {
    console.log(e);

    res.redirect("/register");
  }
};

module.exports.renderLogin = (req, res) => {
  res.render("users/login");
};

module.exports.login = async (req, res) => {
  res.redirect("/");
};

module.exports.renderForgotPassword = (req, res) => {
  res.render("users/forgotPassword");
};

module.exports.emailVerification = function (req, res, next) {
  async.waterfall(
    [
      //functions are first class objects, can pass the values around
      function (done) {
        crypto.randomBytes(20, function (err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function (token, done) {
        User.findOne({ email: req.body.email }, function (err, user) {
          if (!user) {
            return res.redirect("/forgotPassword");
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

          user.save(function (err) {
            done(err, token, user);
          });
        });
      },
      function (token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: emailID,
            pass: pass,
          },
        });
        var mailOptions = {
          to: user.email,
          from: emailID,
          subject: "Node.js Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "/email" +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          console.log("mail sent");

          done(err, "done");
        });
      },
    ],
    function (err) {
      if (err) return next(err);
      res.redirect("/forgotPassword");
    }
  );
};

module.exports.renderToken = function (req, res) {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    function (err, user) {
      if (!user) {
        return res.redirect("/forgotPassword");
      }
      res.render("users/resetByEmail", { token: req.params.token });
    }
  );
};

module.exports.changePassword = function (req, res) {
  async.waterfall(
    [
      function (done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
          },
          function (err, user) {
            if (!user) {
              return res.redirect("/forgotPassword");
            }
            if (req.body.password === req.body.confirm) {
              user.setPassword(req.body.password, function (err) {
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save(function (err) {
                  req.logIn(user, function (err) {
                    done(err, user);
                  });
                });
              });
            } else {
              return res.redirect("/");
            }
          }
        );
      },
      function (user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: emailID,
            pass: pass,
          },
        });
        var mailOptions = {
          to: user.email,
          from: emailID,
          subject: "Your password has been changed",
          text:
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.email +
            " has just been changed.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          done(err);
        });
      },
    ],
    function (err) {
      res.redirect("/");
    }
  );
};

module.exports.logout = (req, res) => {
  req.logout();

  res.redirect("/");
};
