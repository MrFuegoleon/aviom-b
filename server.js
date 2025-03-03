const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { keycloak, memoryStore } = require("./keycloak-config");
const session = require("express-session");
require("dotenv").config();
const bodyParser = require("body-parser");
const passport = require("./passport-config");

const createProjectRoute = require("./routes/createProject");
const openstackRoutes = require("./routes/openstack.js");
const gocardlessRoutes = require("./routes/gocardless.js");
const paypalRoutes = require("./routes/paypal.js");
const authRoutes = require("./routes/login");
const sseRoutes = require("./routes/sse.js");
const packsRoutes = require("./routes/packsRoutes");
const vosFacturesRoutes = require("./routes/vosfactures");
const machineRoutes = require("./routes/machine.js");
const cancelSubscriptionRoute = require("./routes/cancelSubscription");
const summaryRoute = require("./routes/summary.js");


const app = express();
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(bodyParser.json());
app.use(passport.initialize());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "some-secret-key",
    resave: false,
    saveUninitialized: true,
    store: memoryStore,
  })
);

app.use("/api", packsRoutes);
app.use("/api/vosfactures", vosFacturesRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/sse", sseRoutes);
app.use("/api/openstack", openstackRoutes);
app.use("/api/gocardless", gocardlessRoutes);
app.use("/api/paypal", paypalRoutes);
app.use("/api/machine", machineRoutes);
app.use("/api/cancel-subscription", cancelSubscriptionRoute);
app.use("/api/project", createProjectRoute);
app.use("/api/summary", summaryRoute);


app.post("/webhook/gocardless", async (req, res) => {
  try {
    const event = req.body;

    if (event.action === "payment_confirmed") {
      console.log(" Paiement confirmé via GoCardless :", event);

      //  Récupération des infos de paiement
      const paymentDetails = {
        client_name: event.links.customer,
        client_email: event.links.customer_email,
        amount: event.amount / 100, // Convertir en euros
        currency: event.currency,
        payment_id: event.links.payment,
      };

      // Création d'une facture via VosFactures
      const invoiceData = {
        api_token: process.env.VOSFACTURES_API_KEY,
        kind: "invoice",
        number: `GC-${paymentDetails.payment_id}`,
        client_name: paymentDetails.client_name,
        client_email: paymentDetails.client_email,
        items: [
          {
            name: "Achat via GoCardless",
            price_net: paymentDetails.amount,
            quantity: 1,
            tax: 20,
          },
        ],
      };

      const invoiceResponse = await axios.post(
        "https://aviom.vosfactures.fr/invoices.json",
        invoiceData,
        { headers: { "Content-Type": "application/json" } }
      );

      console.log(" Facture créée :", invoiceResponse.data);
    }

    res.status(200).send("Webhook reçu avec succès.");
  } catch (error) {
    console.error("Erreur lors de la création de la facture :", error);
    res.status(500).send("Erreur serveur.");
  }
});

app.get("/", async (req, res) => {
  res.send("Backend Express pour OpenStack est en marche.");
});

app.listen(5000, () => {
  console.log("✅  port 5000");
});
