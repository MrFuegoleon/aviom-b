const express = require("express");
const router = express.Router();
const { findUserByUsername, pool } = require('../db');
const authenticateJWT = require("../middlewares/authenticateJWT");

router.post("/", authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;

    await pool.query(
      "UPDATE users SET eco = 0, duo = 0, trio = 0, flex = 0 WHERE id = ?",
      [userId]
    );

    res.json({ 
      message: "Subscription canceled. All packs have been set to 0. Your project remains (inactive) and can be reactivated if you purchase a new pack." 
    });
  } catch (error) {
    console.error("Error canceling subscription:", error);
    res.status(500).json({ error: "Server error canceling subscription" });
  }
});

module.exports = router;
