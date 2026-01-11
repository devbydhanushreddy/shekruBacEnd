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

/* ===================== ENV ===================== */
const PORT = process.env.PORT || 8000;
const MONGO_URL = process.env.MONGO_URL;
const SALT = Number(process.env.SALT || 10);

/* ===================== MONGO ===================== */
mongoose
  .connect(MONGO_URL, { tls: true })
  .then(() => {
    console.log("✅ MongoDB Connected");
    createDefaultAdmin();
  })
  .catch((err) => console.error("❌ Mongo Error:", err));

/* ===================== SESSION STORE ===================== */
const store = new MongoDBStore({
  uri: MONGO_URL,
  collection: "sessions",
  connectionOptions: { tls: true },
});

store.on("error", (err) => console.error("Session store error:", err));

/* ===================== CORS (CRITICAL FIX) ===================== */
const allowedOrigins = [
  "http://localhost:5173",
  "https://dhanushapp.netlify.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("CORS not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.options("*", cors());

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ===================== SESSION ===================== */
app.use(
  session({
    name: "connect.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      httpOnly: true,
      secure: true, // MUST be true on Render
      sameSite: "none", // REQUIRED for Netlify
      maxAge: 1000 * 60 * 60,
    },
  })
);

/* ===================== AUTH MIDDLEWARE ===================== */
const isAuth = (req, res, next) => {
  if (req.session.isAuth) return next();
  return res.status(401).send("Unauthorized");
};

const isAdmin = (req, res, next) => {
  if (req.session.role === "admin") return next();
  return res.status(403).send("Admin only");
};

/* ===================== ROUTES ===================== */

/* ---- ADD USER ---- */
app.post("/add/user", isAuth, isAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    validateUsr({ name, email, password });

    if (await User.findOne({ email }))
      return res.status(409).send("User exists");

    const hashed = await bcrypt.hash(password, SALT);
    await User.create({ name, email, password: hashed, role: role || "user" });

    res.status(201).send("User added");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* ---- DASHBOARD ---- */
app.get("/dashboard", isAuth, async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = 5;
  const skip = (page - 1) * limit;

  const totalUsers = await User.countDocuments();
  const users = await User.find({}, "-password")
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 });

  res.json({
    users,
    page,
    totalPages: Math.ceil(totalUsers / limit),
    role: req.session.role,
  });
});

/* ---- LOGIN ---- */
app.post("/api/auth/login", async (req, res) => {
  const email = req.body.email?.trim().toLowerCase();
  const password = req.body.password?.trim();

  // ADMIN LOGIN
  if (
    email === process.env.ADMIN_EMAIL?.toLowerCase() &&
    password === process.env.ADMIN_PASSWORD
  ) {
    req.session.isAuth = true;
    req.session.role = "admin";
    return res.status(200).json({ role: "admin" });
  }

  // USER LOGIN
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send("Email not found");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).send("Wrong password");

  const otp = generateOTP();
  req.session.loginOTP = otp;
  req.session.otpExpiry = Date.now() + 5 * 60 * 1000;
  req.session.tempUser = user.email;
  req.session.role = user.role;
  req.session.isAuth = false;

  await sendMail({ email: user.email, name: user.name, otp });
  res.send("OTP sent");
});

/* ---- VERIFY OTP ---- */
app.post("/api/auth/verify-otp", (req, res) => {
  const { otp } = req.body;

  if (!req.session.loginOTP) return res.status(400).send("OTP missing");
  if (Date.now() > req.session.otpExpiry)
    return res.status(401).send("OTP expired");

  if (Number(otp) !== req.session.loginOTP)
    return res.status(401).send("Invalid OTP");

  req.session.isAuth = true;
  req.session.loginOTP = null;
  req.session.otpExpiry = null;

  res.send("Login success");
});

/* ---- LOGOUT ---- */
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    res.send("Logged out");
  });
});

/* ---- ROOT ---- */
app.get("/", (_, res) => res.send("Backend running 🚀"));

/* ===================== START ===================== */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
