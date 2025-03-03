const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'd1cdf1v5dggvbf1gbb1fg5';

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  let token = null;
  console.log("Authorization Header:", req.headers.authorization);
  console.log("Query Token:", req.query.token);


  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1]; 
  } else if (req.query && req.query.token) {
    token = req.query.token; 
  }

  if (!token) {
    return res.status(401).json({ message: 'Token manquant' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token invalide ou expiré' });
    }
    req.user = decoded
    next();
    console.log(token);
    console.log(req.user);
  });
};


module.exports = authenticateJWT;