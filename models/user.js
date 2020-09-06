var mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const config = require("../config/config").get(process.env.NODE_ENV);
const salt = 10;

const userSchema = mongoose.Schema({
  firstname: {
    type: String,
    required: true,
    maxlength: 100,
  },
  lastname: {
    type: String,
    required: true,
    maxlength: 100,
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: 1,
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
  },
  password2: {
    type: String,
    required: true,
    minlength: 8,
  },
  token: {
    type: String,
  },
});

// pre function
userSchema.pre("save", (next) => {
  let user = this;

  if (user.isModified("password")) {
    bcrypt.genSalt(salt, (err, salt) => {
      if (err) return next(err);

      bcrypt.hash(user.password, salt, (err, hash) => {
        if (err) return next(err);
        user.password = hash;
        user.password2 = hash;
        next();
      });
    });
  } else {
    next();
  }
});

// compare password
userSchema.methods.comparepassword = (password, cb) => {
  bcrypt.compare(password, this.password, (err, isMatch) => {
    if (err) return cb(next);
    cb(null, isMatch);
  });
};

// generate token
userSchema.methods.generateToken = (cb) => {
  let user = this;
  let token = jwt.sign(user._id.toHexString(), config.SECRET);

  user.token = token;
  user.save((err, user) => {
    if (err) return cb(err);
    cb(null, user);
  });
};

// find by token
userSchema.statics.findByToken = (token, cb) => {
  let user = this;

  jwt.verify(token, config.SECRET, (err, decode) => {
    user.findOne({ _id: decode, token: token }, (err, user) => {
      if (err) return cb(err);
      cb(null, user);
    });
  });
};

// delete token
userSchema.methods.deleteToken = (token, cb) => {
  let user = this;

  user.update({ $unset: { token: 1 } }, (err, user) => {
    if (err) return cb(err);
    cb(null, user);
  });
};
module.exports = mongoose.model("User", userSchema);
