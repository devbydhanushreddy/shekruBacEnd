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
  .connect(MONGO_URL, { tls: true })
  .then(() => {
    console.log("✅ MongoDB Connected");
    createDefaultAdmin();
  })
  .catch((err) => console.error("❌ Mongo Error:", err));

// ----------------- SESSION -----------------
const store = new MongoDBStore({
  uri: MONGO_URL,
  collection: "sessions",
  connectionOptions: { tls: true },
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
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ----------------- CORS (Production-Ready) -----------------
const allowedOrigins = [
  "http://localhost:5173",               // dev
  "https://dhanushapp.netlify.app",      // production frontend
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (like Postman)
      if (!origin) return callback(null, true);
      if (!allowedOrigins.includes(origin)) {
        const msg = `CORS policy does not allow access from ${origin}`;
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ----------------- MIDDLEWARE -----------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------------- AUTH MIDDLEWARE -----------------
const isAuth = (req, res, next) => {
  if (req.session.isAuth) return next();
  return res.status(401).send("Unauthorized");
};

const isAdmin = (req, res, next) => {
  if (req.session.role === "admin") return next();
  return res.status(403).send("Admin access only");
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
    if (role && email !== process.env.ADMIN_EMAIL) user.role = role;

    if (password) user.password = await bcrypt.hash(password, SALT);

    await user.save();
    res.status(200).send("User updated successfully");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ----------------- DELETE USER -----------------
app.delete("/api/user/:id", isAuth, isAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).send("User not found");

    res.status(200).send("User deleted successfully");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ----------------- DASHBOARD -----------------
app.get("/dashboard", isAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
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
    res.clearCookie("connect.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    });
    res.status(200).send("Logged out successfully");
  });
});

// ----------------- LOGIN -----------------
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const emailInput = email?.trim().toLowerCase();
  const passwordInput = password?.trim();
  const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD?.trim();

  // ----- ADMIN LOGIN -----
  if (emailInput === adminEmail && passwordInput === adminPassword) {
    req.session.isAuth = true;
    req.session.role = "admin";
    return res.status(200).json({ success: true, role: "admin" });
  }

  // ----- NORMAL USER LOGIN (OTP) -----
  try {
    const user = await User.findOne({ email: emailInput });
    if (!user) return res.status(404).send("Email not registered");

    const isMatch = await bcrypt.compare(passwordInput, user.password);
    if (!isMatch) return res.status(401).send("Incorrect password");

    const otp = generateOTP();
    req.session.loginOTP = otp;
    req.session.otpExpiry = Date.now() + 5 * 60 * 1000;
    req.session.tempUser = user.email;
    req.session.role = user.role;
    req.session.isAuth = false;

    await sendMail({ email: user.email, name: user.name, otp });
    return res.status(200).send("OTP sent to registered email");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error");
  }
});

// ----------------- VERIFY OTP -----------------
app.post("/api/auth/verify-otp", (req, res) => {
  const { otp } = req.body;

  if (!req.session.loginOTP || !req.session.otpExpiry)
    return res.status(400).send("OTP not generated");

  if (Date.now() > req.session.otpExpiry) {
    req.session.loginOTP = null;
    req.session.otpExpiry = null;
    req.session.tempUser = null;
    return res.status(401).send("OTP expired");
  }

  if (Number(otp) !== req.session.loginOTP)
    return res.status(401).send("Invalid OTP");

  req.session.isAuth = true;
  req.session.loginOTP = null;
  req.session.otpExpiry = null;

  return res.status(200).send("Login successful");
});

// ----------------- ROOT -----------------
app.get("/", (req, res) => res.status(200).send("Server running successfully"));

// ----------------- START SERVER -----------------
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
