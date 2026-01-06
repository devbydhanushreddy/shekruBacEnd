const isAuth = (req, res, next) => {
  if (req.session.isAuth && req.session.isVerified) {
    next();
  } else {
    res.status(401).send("User not verified");
  }
};
module.exports = { isAuth };
