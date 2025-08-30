const jwt = require("jsonwebtoken");
const { JWT_ADMIN_PASSWORD } = require("../config");
const admin = require("../routes/admin");

function adminMiddleware(req, res, next) {
  const token = req.headers.token;
  const decoded = jwt.verify(token, JWT_ADMIN_PASSWORD);

  if (decoded) {
    req.adminId = decoded.id
    next();
  } else {
    res.json({
      message: "You are not logged in",
    });
  }
}

module.exports = {
  adminMiddleware: adminMiddleware,
};