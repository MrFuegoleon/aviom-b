const express = require('express');
const router = express.Router();
const app = express();
const axios = require("axios");


// ────────────────────────────────────────────────────────────────────────────────
// 🔹 **PAYPAL CONFIGURATION**
// ────────────────────────────────────────────────────────────────────────────────

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;
const BASE_URL = "https://api-m.sandbox.paypal.com";

console.log("📌 PAYPAL_CLIENT_ID:", PAYPAL_CLIENT_ID);
console.log("📌 PAYPAL_SECRET:", PAYPAL_SECRET);

// ✅ Route pour créer un paiement PayPal
router.post("/create-payment", async (req, res) => {

  try {
    const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString("base64");
    const response = await axios.post(`${BASE_URL}/v2/checkout/orders`, {
      intent: "CAPTURE",
      purchase_units: [{ amount: { currency_code: "EUR", value: "10.00" } }]
    }, {
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Basic ${auth}`
      }
    });

    res.json({ orderID: response.data.id });
  } catch (error) {
    console.error("❌ Erreur PayPal:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Erreur lors de la création du paiement PayPal" });
  }
});

// ✅ Route pour récupérer le Client ID PayPal
router.get("/client-id", (req, res) => {

  if (!PAYPAL_CLIENT_ID) {
    return res.status(500).json({ error: "❌ Client ID PayPal non défini." });
  }
  res.json({ clientId: PAYPAL_CLIENT_ID });
});


module.exports = router;
