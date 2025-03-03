const express = require("express");
const axios = require("axios");
require("dotenv").config();

const router = express.Router();

// Endpoint pour récupérer les factures depuis VosFactures
router.get("/invoices", async (req, res) => {
    try {
        const response = await axios.get(`https://aviom.vosfactures.fr/invoices.json`, {
            params: {
                api_token: process.env.VOSFACTURES_API_KEY,
                period: "this_month",
                page: 1,
                per_page: 25
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error("Erreur API VosFactures :", error);
        res.status(500).json({ error: "Erreur lors de la récupération des factures." });
    }
});

// Endpoint pour créer une nouvelle facture
router.post("/create-invoice", async (req, res) => {
    try {
        const invoiceData = {
            api_token: process.env.VOSFACTURES_API_KEY,
            kind: "invoice", // Type : "invoice" pour une facture, "estimate" pour un devis
            number: "2025-001",
            client_name: req.body.client_name,
            client_email: req.body.client_email,
            items: [
                {
                    name: req.body.item_name,
                    price_net: req.body.price_net,
                    quantity: req.body.quantity,
                    tax: req.body.tax
                }
            ]
        };

        const response = await axios.post(`https://aviom.vosfactures.fr/invoices.json`, invoiceData, {
            headers: { "Content-Type": "application/json" }
        });

        res.json(response.data);
    } catch (error) {
        console.error("Erreur lors de la création de la facture :", error);
        res.status(500).json({ error: "Impossible de créer la facture." });
    }
});

module.exports = router;
