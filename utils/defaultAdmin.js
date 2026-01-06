const bcrypt = require("bcrypt");
const User = require("../models/User");

exports.createDefaultAdmin = async () => {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  const exists = await User.findOne({ email: adminEmail });
  if (exists) return;

  const hashed = await bcrypt.hash(adminPassword, 10);

  await User.create({
    name: "SuperAdmin",
    email: adminEmail,
    password: hashed,
    role: "admin",
  });

  console.log("Default Admin Created");
};
