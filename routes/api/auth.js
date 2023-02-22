const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");
const { createError, createHashPassword } = require("../../helpers");

const User = require("../../models/users");
const { authorize, upload } = require("../../middlewares");

const registerUserSchema = Joi.object({
  name: Joi.string().required(),
  password: Joi.string().min(6).required(),
  email: Joi.string()
    // eslint-disable-next-line no-useless-escape
    .pattern(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/)
    .required(),
});

const loginUserSchema = Joi.object({
  password: Joi.string().min(6).required(),
  email: Joi.string()
    // eslint-disable-next-line no-useless-escape
    .pattern(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/)
    .required(),
});

const { SECRET_KEY } = process.env;
const router = express.Router();

router.post("/register", async (req, res, next) => {
  try {
    const { error } = registerUserSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }

    const { email, password, name } = req.body;

    const user = await User.findOne({ email });
    if (user) {
      throw createError(409, "Email in use");
    }

    const hashPassword = await createHashPassword(password);
    const avatarURL = gravatar.url(email);

    const newUser = await User.create({
      email,
      name,
      password: hashPassword,
      avatarURL,
    });
    res.status(201).json({
      user: {
        email: newUser.email,
        name: newUser.name,
        subscription: newUser.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { error } = loginUserSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      throw createError(401, "Credentials are wrong");
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw createError(401, "Credentials are wrong");
    }
    const payload = { id: user._id };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

    await User.findByIdAndUpdate({ _id: user._id }, { token });

    res.json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
        avatarURL: user.avatarURL,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: "" });
    res.json({
      message: "Logout successfull",
    });
  } catch (error) {
    next(error);
  }
});

router.get("/current", authorize, async (req, res, next) => {
  try {
    const { email, name } = req.user;
    res.json({
      email,
      name,
    });
  } catch (error) {
    next(error);
  }
});

router.patch("/users", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    const { subscription } = req.body;
    const subscriptionTypes = ["starter", "pro", "business"];
    const isValid = subscriptionTypes.some((sub) => sub === subscription);
    if (!isValid) throw createError(400, "Subscribe type is wrong");

    const { email } = await User.findByIdAndUpdate({ _id }, { subscription });

    return res.status(200).json({ email, subscription });
  } catch (error) {
    next(error);
  }
});

router.patch("/avatars", authorize, upload, async (req, res, next) => {
  try {
    const { _id } = req.user;
    const { path: tempDir, originalname } = req.file;
    const [extension] = originalname.split(".").reverse();
    const newName = `${_id}.${extension}`;

    const uploadDir = path.join(
      __dirname,
      "../../",
      "public",
      "avatars",
      newName
    );

    const image = await Jimp.read(tempDir);
    await image.resize(250, 250).write(tempDir);

    await fs.rename(tempDir, uploadDir);

    const avatarURL = path.join("/avatars", newName);
    await User.findByIdAndUpdate(_id, { avatarURL });
    res.status(201).json(avatarURL);
  } catch (error) {
    await fs.unlink(req.file.path);
    next(error);
  }
});

module.exports = router;
