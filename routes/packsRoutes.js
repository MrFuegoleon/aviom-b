const express = require("express");
const db = require("../db");
const router = express.Router();

// 📌 Récupérer tous les packs
router.get("/packs", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM packs");
    res.json(rows);
  } catch (error) {
    console.error("❌ Erreur récupération packs:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// 📌 Récupérer tous les Flex
router.get("/Flex", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM Flex");
    res.json(rows);
  } catch (error) {
    console.error("❌ Erreur récupération flex:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});
// 📌 Récupérer les informations personnelles
router.get("/informations_personnelles", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM informations_personnelles LIMIT 1");
    res.json(rows);
  } catch (error) {
    console.error("❌ Erreur récupération informations_personnelles:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// 📌 Mettre à jour les informations personnelles
router.put("/informations_personnelles", async (req, res) => {
  const { entite, raison_sociale, numero_siret, nom, prenom, telephone, email, adresse, code_postal, ville, pays } = req.body;

  try {
    const [result] = await db.query(
      `UPDATE informations_personnelles 
       SET entite=?, raison_sociale=?, numero_siret=?, nom=?, prenom=?, telephone=?, email=?, adresse=?, code_postal=?, ville=?, pays=?
       WHERE id = 1`,
      [entite, raison_sociale, numero_siret, nom, prenom, telephone, email, adresse, code_postal, ville, pays]
    );

    console.log("🔍 Nombre de lignes affectées :", result.affectedRows);

    if (result.affectedRows > 0) {
      res.json({ message: "✅ Informations mises à jour avec succès !" });
    } else {
      res.status(400).json({ error: "⚠️ Aucune mise à jour effectuée, ID incorrect ?" });
    }
  } catch (error) {
    console.error("❌ Erreur mise à jour des informations :", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});


// 📌 Récupérer tous les Packs Perso
router.get("/packs_perso", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM packs_perso");
    res.json(rows);
  } catch (error) {
    console.error("❌ Erreur récupération packs_perso:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// 📌 Récupérer tous les VM Packs
router.get("/vm_packs", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM vm_packs");
    res.json(rows);
  } catch (error) {
    console.error("❌ Erreur récupération vm_packs:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

module.exports = router;
