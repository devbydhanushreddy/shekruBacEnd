require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const cors = require("cors");
const { generateOTP, sendMail } = require("./utils/verification");
const User = require("./models/User");
const { validateUsr } = require("./utils/inputValidation");
const { createDefaultAdmin } = require("./utils/defaultAdmin");

const app = express();
const SALT = Number(process.env.SALT);
const PORT = process.env.PORT || 8000;
const MONGO_URL = process.env.MONGO_URL;

// ----------------- MONGO -----------------
mongoose
  .connect(MONGO_URL, {
    tls: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ Mongo Error:", err));
// ----------------- SESSION -----------------
const store = new MongoDBStore({
  uri: MONGO_URL,
  collection: "sessions",
  connectionOptions: {
    tls: true,
  },
});
store.on("error", (error) => {
  console.error("Session store error:", error);
});
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      httpOnly: true,
      secure: true, // REQUIRED on Render (HTTPS)
      sameSite: "none", // REQUIRED for Netlify → Render
      maxAge: 1000 * 60 * 60,
    },
  })
);

// ----------------- CORS -----------------

const allowedOrigins = [
  "http://localhost:5173", // local frontend
  process.env.FRONTEND_URL, // production frontend
].filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

// ----------------- MIDDLEWARE -----------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------------- AUTH MIDDLEWARE -----------------
const isAuth = (req, res, next) => {
  if (req.session.isAuth) next();
  else return res.status(401).send("Unauthorized");
};

const isAdmin = (req, res, next) => {
  if (req.session.role === "admin") next();
  else return res.status(403).send("Admin access only");
};

// ----------------- ADD USER -----------------
app.post("/add/user", isAuth, isAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    validateUsr({ name, email, password });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, SALT);

    await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || "user",
    });
    res.status(201).send("User added successfully");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ----------------- EDIT USER -----------------
app.put("/api/user/:id", isAuth, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, password, role } = req.body;

    const user = await User.findById(id);
    if (!user) return res.status(404).send("User not found");

    if (name) user.name = name;
    if (email) user.email = email;
    if (role && email !== process.env.ADMIN_EMAIL) {
      user.role = role;
    }

    if (password) {
      const hashPass = await bcrypt.hash(password, SALT);
      user.password = hashPass;
    }

    await user.save();
    res.status(200).send("User updated successfully");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ----------------- DELETE USER -----------------
app.delete("/api/user/:id", isAuth, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).send("User not found");

    res.status(200).send("User deleted successfully");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ----------------- DASHBOARD -----------------
// app.get("/dashboard", isAuth, async (req, res) => {
//   const users = await User.find({}, "-password");
//   res.json({ users, role: req.session.role });
// });
app.get("/dashboard", isAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // current page
    const limit = 5; // users per page
    const skip = (page - 1) * limit;

    const totalUsers = await User.countDocuments();

    const users = await User.find({}, "-password")
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    res.status(200).json({
      users,
      currentPage: page,
      totalPages: Math.ceil(totalUsers / limit),
      totalUsers,
      role: req.session.role,
    });
  } catch (err) {
    res.status(500).send("Error loading dashboard");
  }
});

// ----------------- LOGOUT -----------------
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.status(200).send("Logged out successfully");
  });
});
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  /* ----------Default ADMIN LOGIN (NO OTP) ---------- */
  if (
    email === process.env.ADMIN_EMAIL &&
    password === process.env.ADMIN_PASSWORD
  ) {
    req.session.isAuth = true;
    req.session.role = "admin";
    return res.redirect("/dashboard");
  }

  try {
    const user = await User.findOne({ email });

    /* EMAIL NOT FOUND */
    if (!user) {
      return res.status(404).send("Email not registered");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    /*WRONG PASSWORD */
    if (!isMatch) {
      return res.status(401).send("Incorrect password");
    }

    /* ---------- NORMAL USER → OTP LOGIN ---------- */
    const otp = generateOTP();

    req.session.loginOTP = otp;
    req.session.otpExpiry = Date.now() + 5 * 60 * 1000;
    req.session.tempUser = user.email;
    req.session.role = user.role;
    req.session.isAuth = false;

    await sendMail({
      email,
      name: user.name,
      otp,
    });

    return req.session.save(() => {
      res.status(200).send("OTP sent to registered email");
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send("Server error");
  }
});
app.post("/api/auth/verify-otp", (req, res) => {
  const { otp } = req.body;

  /* ❌ OTP NOT GENERATED */
  if (!req.session.loginOTP || !req.session.otpExpiry) {
    return res.status(400).send("OTP not generated");
  }

  /* ❌ OTP EXPIRED */
  if (Date.now() > req.session.otpExpiry) {
    // cleanup
    req.session.loginOTP = null;
    req.session.otpExpiry = null;
    req.session.tempUser = null;

    return res.status(401).send("OTP expired");
  }

  /* ❌ OTP INVALID */
  if (Number(otp) !== req.session.loginOTP) {
    return res.status(401).send("Invalid OTP");
  }

  /* ✅ OTP VERIFIED → LOGIN SUCCESS */
  req.session.isAuth = true;

  // cleanup OTP data
  req.session.loginOTP = null;
  req.session.otpExpiry = null;

  return req.session.save(() => {
    res.status(200).send("Login successful");
  });
});
app.get("/", (req, res) =>
  res.status(200).send("server connection successful")
);
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
