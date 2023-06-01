const Router = require("express");
const User = require("../models/User");
const config = require("config");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../middleware/auth.middleware");
const { check, validationResult } = require("express-validator");
const fileService = require("../services/fileService");
const File = require("../models/File");
const router = new Router();

router.post(
  "/registration",
  [
    check("email", "Uncorrect email").isEmail(),
    check(
      "password",
      "password must be more than 3 but not more than 18 characters"
    ).isLength({ min: 3, max: 18 }),
  ],
  async (req, res) => {
    try {
      console.log(req.body);
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Uncorrect request", errors });
      }
      const { email, password } = req.body;

      const candidate = await User.findOne({ email });

      if (candidate) {
        return res
          .status(400)
          .json({ message: `User with email ${email} already exist` });
      }
      const hashPassword = await bcrypt.hash(password, 8);
      const user = new User({ email, password: hashPassword });
      await user.save();
      await fileService.createDir(req, new File({ user: user.id, name: "" }));
      res.json({ message: "User was created" });
    } catch (error) {
      console.log(error);
      res.send({ message: "Server error" });
    }
  }
);

router.post(
  "/login",

  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: "User not found" });
      }
      const isPassValid = bcrypt.compareSync(password, user.password); // Сравнение пользовательского пароля с зашифрованным
      if (!isPassValid) {
        return res.status(400).json({ message: "Invalid password" });
      }
      const token = jwt.sign({ id: user.id }, config.get("secretKey"), {
        // JWT token  1 - Объект с данными, который мы помещает в токен
        expiresIn: "1h", // 2 - передаем секретный ключ 3 - сколько времени токен будет существовать
      });
      return res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          diskSpace: user.diskSpace,
          usedSpace: user.usedSpace,
          avatar: user.avatar,
        },
      });
    } catch (error) {
      console.log(error);
      res.send({ message: "Server error" });
    }
  }
);

router.get("/auth", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.user.id });
    const token = jwt.sign({ id: user.id }, config.get("secretKey"), {
      expiresIn: "1h",
    });
    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        diskSpace: user.diskSpace,
        usedSpace: user.usedSpace,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    console.log(error);
    res.send({ message: "Server error" });
  }
});

module.exports = router;
