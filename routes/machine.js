const express = require('express');
const router = express.Router();
const { findUserByUsername, pool } = require('../db');
const authenticateJWT = require('../middlewares/authenticateJWT');

router.get("/", authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const [rows] = await pool.query("SELECT eco, duo, trio, flex FROM users WHERE id = ?", [userId]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Return the pack info
    res.json({
      eco: rows[0].eco,
      duo: rows[0].duo,
      trio: rows[0].trio,
      flex: rows[0].flex
    });
  } catch (error) {
    console.error("Error fetching user packs:", error);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
