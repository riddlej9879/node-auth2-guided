const jwt = require("jsonwebtoken");

function restrict(role) {
  const roles = ["basic", "paid", "premium", "admin"];
  return async (req, res, next) => {
    const authError = {
      message: "Invalid credentials",
    };

    try {
      // assure the token gets passed to the API as an authorization header
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json(authError);
      }

      // decode the token, re-sign the paylod, and check if signature is valid
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).json(authError);
        }

        // if (decoded.userRole === "basic") {
        //   return res.status(401).json({ message: "Admins only" });
        // }

        if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
          return res.status(403).json({ message: "You shall not pass" });
        }

        // we know the user is authorized at this point
        // make the token's payload abailable to other middleware functions
        req.token = decoded;
        next();
      });
    } catch (err) {
      next(err);
    }
  };
}

module.exports = restrict;
