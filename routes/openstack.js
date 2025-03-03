const express = require("express");
const axios = require("axios");
const fs = require("fs");
const router = express.Router();
const authenticateJWT = require('../middlewares/authenticateJWT');


const OS_IDENTITY_URL = process.env.OS_IDENTITY_URL;
const OS_USERNAME = process.env.OS_USERNAME;
const OS_PASSWORD = process.env.OS_PASSWORD;
// const OS_PROJECT_NAME = process.env.OS_PROJECT_NAME;
const OS_DOMAIN_ID = process.env.OS_DOMAIN_ID;

const OS_NOVA_URL = process.env.OS_NOVA_URL;

const KEYPAIR_NAME = process.env.KEYPAIR_NAME;
const KEYPAIR_FILE = process.env.KEYPAIR_FILE;

//  To get a token
async function getAuthToken(projectId) {
  try {
    const authPayload = {
      auth: {
        identity: {
          methods: ["password"],
          password: {
            user: {
              name: OS_USERNAME,
              domain: { id: OS_DOMAIN_ID },
              password: OS_PASSWORD,
            },
          },
        },
        scope: {
          project: {
            id: projectId
          },
        },
      },
    };

    const response = await axios.post(`${OS_IDENTITY_URL}/auth/tokens`, authPayload, {
      headers: { "Content-Type": "application/json" },
    });


    return response.headers["x-subject-token"];
  } catch (error) {
    console.error("Erreur d'authentification:", error.response?.data || error.message);
    throw new Error("Authentification OpenStack échouée");
  }
}

//  Check/Create key pair

async function ensureKeypairExists(token, projectId) {
  try {
    // Try to get the keypair by including the project id in headers (if needed)
    await axios.get(`${OS_NOVA_URL}/os-keypairs/${KEYPAIR_NAME}`, {
      headers: { 
        "X-Auth-Token": token,
        "X-Project-Id": projectId  // pass the project id here
      },
    });
    console.log(`La paire de clés "${KEYPAIR_NAME}" existe déjà.`);
  } catch (err) {
    if (err.response && err.response.status === 404) {
      console.log(`La paire de clés "${KEYPAIR_NAME}" n'existe pas, création en cours...`);
      const createResponse = await axios.post(
        `${OS_NOVA_URL}/os-keypairs`,
        { keypair: { name: KEYPAIR_NAME } },
        {
          headers: { 
            "X-Auth-Token": token, 
            "Content-Type": "application/json",
            "X-Project-Id": projectId  // include the project id here as well
          }
        }
      );

      const privateKey = createResponse.data.keypair.private_key;
      if (privateKey) {
        fs.writeFileSync(KEYPAIR_FILE, privateKey, { mode: 0o600 });
        console.log(`Clé privée sauvegardée dans ${KEYPAIR_FILE}`);
      }
    } else {
      throw err;
    }
  }
}


// Create a VM
router.post("/create-vm",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;
  try {
    const { flavorRef, name } = req.body;
    const token = await getAuthToken(projectId);
    await ensureKeypairExists(token,projectId);

    const serverPayload = {
      server: {
        name: `${name || "myVM"}-${projectId}`, // Use the name from the request or default to "myVM"
        imageRef: "8e0a53a0-f84b-4e0f-b0f5-89b8414fc468", // Replace with your image ID
        flavorRef: flavorRef, // Use the flavorRef from the request
        networks: [{ uuid: "6bbb744b-3f6e-4baa-947e-0964f6aa6fd1" }], // Replace with your network ID
        key_name: KEYPAIR_NAME,
      },
    };

    const novaResponse = await axios.post(`${OS_NOVA_URL}/servers`, serverPayload, {
      headers: { "X-Auth-Token": token, "Content-Type": "application/json" },
    });

    res.status(200).json({ message: "VM créée avec succès", data: novaResponse.data.server });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la création de la VM", error: error.response?.data || error.message });
  }
});

// Reboot a VM
router.post("/reboot-vm/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;
  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;
    const { type } = req.body;

    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { reboot: { type: type || "SOFT" } }, // Default to SOFT if type is not provided
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "VM redémarrée avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors du redémarrage de la VM", error: error.response?.data || error.message });
  }
});

// Resize VM (Change RAM, CPU and Disk)
router.put("/resize-vm/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;
  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;
    const { ram, vcpus, disk } = req.body;

    // Check if parameters are good for available flavors
    if (!ram || !vcpus || !disk) {
      return res.status(400).json({ message: "RAM, CPU et disque sont obligatoires." });
    }

    // Get list of flavors
    const flavorsResponse = await axios.get(`${OS_NOVA_URL}/flavors/detail`, {
      headers: { "X-Auth-Token": token },
    });

    const flavors = flavorsResponse.data.flavors;

    // Check if there is nay flavor linked to request flavor parameters
    const matchingFlavor = flavors.find(f => 
      f.ram === parseInt(ram) && f.vcpus === parseInt(vcpus) && f.disk === parseInt(disk)
    );

    if (!matchingFlavor) {
      return res.status(404).json({ message: "Aucun flavor ne correspond aux spécifications fournies." });
    }

    // Change the CM with that new flavor
    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { resize: { flavorRef: matchingFlavor.id } },
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "VM mise à jour avec succès.", flavor: matchingFlavor.id });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la mise à jour de la VM", error: error.response?.data || error.message });
  }
});


// Delete a VM
router.delete("/delete-vm/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;

    await axios.delete(`${OS_NOVA_URL}/servers/${id}`, {
      headers: { "X-Auth-Token": token },
    });

    res.json({ message: "VM supprimée avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la suppression de la VM", error: error.response?.data || error.message });
  }
});

// Run a VM
router.post("/start-vm/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;

    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { "os-start": null },
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "VM démarrée avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors du démarrage de la VM", error: error.response?.data || error.message });
  }
});

// Stop the VM
router.post("/stop-vm/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;

    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { "os-stop": null },
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "VM arrêtée avec succès" });
  } catch (error) {
    res.status(500).json({ message: " Erreur lors de l'arrêt de la VM", error: error.response?.data || error.message });
  }
});

// List all VM of the project
router.get("/list-vms",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;
  console.log(projectId);

  try {
    const token = await getAuthToken(projectId);

    const response = await axios.get(`${OS_NOVA_URL}/servers/detail`, {
      headers: { "X-Auth-Token": token },
    });

    res.json({ message: "Liste des VMs récupérée", data: response.data.servers });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la récupération des VMs", error: error.response?.data || error.message });
  }
});

// Get all flavors
router.get("/flavors",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);

    const response = await axios.get(`${OS_NOVA_URL}/flavors/detail`, {
      headers: { "X-Auth-Token": token },
    });

    res.json({ message: "Flavors récupérés", data: response.data.flavors });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la récupération des flavors", error: error.response?.data || error.message });
  }
});

// Confirm resizing 
router.post("/confirm-resize/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;

    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { confirmResize: null },
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "Redimensionnement confirmé avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de la confirmation du redimensionnement", error: error.response?.data || error.message });
  }
});

// Canceled resizing
router.post("/revert-resize/:id",authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);
    const { id } = req.params;

    await axios.post(
      `${OS_NOVA_URL}/servers/${id}/action`,
      { revertResize: null },
      { headers: { "X-Auth-Token": token, "Content-Type": "application/json" } }
    );

    res.json({ message: "Redimensionnement annulé avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur lors de l'annulation du redimensionnement", error: error.response?.data || error.message });
  }
});


router.get('/servers/:vmId',authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id;

  try {
    const token = await getAuthToken(projectId);

    if (!token) {
      return res.status(401).json({ error: 'Token missing' });
    }

    const vmId = req.params.vmId;
    
    // Request VM details from the Nova API
    const response = await axios.get(`${OS_NOVA_URL}/servers/${vmId}`, {
      headers: {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
      }
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching VM details:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ error: error.response?.data || error.message });
  }
});

module.exports = router;
