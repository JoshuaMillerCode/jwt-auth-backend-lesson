const jwt = require('jsonwebtoken');

// bouncer
function verifyToken(req, res, next) {
  try {
    if (!req.headers.authorization) {
      throw new Error('No token provided');
    }

    const token = req.headers.authorization.split(' ')[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // attaching the user to the request object
    req.user = decoded.payload;

    next();
  } catch (err) {
    res.status(401).json({ err: err.message });
  }
}

module.exports = verifyToken;
