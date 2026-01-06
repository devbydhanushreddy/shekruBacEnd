const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

exports.generateOTP = () => Math.floor(100000 + Math.random() * 900000);

exports.sendMail = async ({ email, name, otp }) => {
  const html = `
    <h3>Hello ${name}</h3>
    <p>Your OTP is:</p>
    <h2>${otp}</h2>
    <p>Valid for 5 minutes</p>
  `;

  return await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Login OTP",
    html,
  });
};
