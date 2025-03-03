const express = require('express');
const router = express.Router();
const app = express();
const axios = require("axios");

// ────────────────────────────────────────────────────────────────────────────────
// 🔹 **GOCARDLESS CONFIGURATION**
// ────────────────────────────────────────────────────────────────────────────────

const GOCARDLESS_ACCESS_TOKEN = process.env.GOCARDLESS_ACCESS_TOKEN;
const GOCARDLESS_API_URL = "https://api-sandbox.gocardless.com";

console.log("📌 GOCARDLESS_ACCESS_TOKEN:", GOCARDLESS_ACCESS_TOKEN);

// ✅ Route pour créer un paiement GoCardless
router.post("/create-payment", async (req, res) => {

  try {
    const response = await axios.post(
      `${GOCARDLESS_API_URL}/payments`,
      {
        payments: {
          amount: 1000, // 10.00 EUR (GoCardless utilise les centimes)
          currency: "EUR",
          links: { mandate: "MD00169GANW3RS" } // À remplacer par un mandat valide
        }
      },
      {
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${GOCARDLESS_ACCESS_TOKEN}`,
          "GoCardless-Version": "2015-07-06"
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("❌ Erreur GoCardless:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Erreur lors de la création du paiement GoCardless" });
  }
});


module.exports = router;
