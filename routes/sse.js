const express = require("express");
const axios = require("axios");
require("dotenv").config();
const router = express.Router();
const authenticateJWT = require('../middlewares/authenticateJWT');

const OS_IDENTITY_URL = process.env.OS_IDENTITY_URL;
const OS_USERNAME = process.env.OS_USERNAME;
const OS_PASSWORD = process.env.OS_PASSWORD;
const OS_DOMAIN_ID = process.env.OS_DOMAIN_ID;

const OS_NOVA_URL = process.env.OS_NOVA_URL;

//  To get a token
async function getAuthToken(projectId) {
  console.log(projectId);
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


// Function to get VM status from Nova API
async function getVmStatus(vmId, token) {
  try {
    const response = await axios.get(`${OS_NOVA_URL}/servers/${vmId}`, {
      headers: {
        "X-Auth-Token": token,
        "Content-Type": "application/json",
      },
    });
    
    return response.data.server.status;
  } catch (error) {
    console.error("Error fetching VM status:", error.response?.data || error.message);
    throw error;
  }
}

// SSE endpoint for streaming VM status updates
router.get("/vm-status", authenticateJWT, async (req, res) => {
    const ProjectId = req.user.project_id;
    console.log('ProjectId :',ProjectId);

  // Set SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  // Retrieve vmId from query parameters
  const vmId = req.query.vmId;
  if (!vmId) {
    res.write("data: " + JSON.stringify({ error: "Missing vmId" }) + "\n\n");
    res.end();
    return;
  }
  // Get OpenStack token using the project ID attached to req.user (set by authenticateJWT)
  let token;
  try {
    token = await getAuthToken(ProjectId);
  } catch (error) {
    res.write("data: " + JSON.stringify({ error: "Failed to get OpenStack token" }) + "\n\n");
    res.end();
    return;
  }

  // Function to send an SSE message with the current VM status
  const sendStatus = async () => {
    try {
      const status = await getVmStatus(vmId, token);
      res.write(`data: ${JSON.stringify({ status })}\n\n`);
    } catch (error) {
      res.write(`data: ${JSON.stringify({ error: "Failed to fetch VM status", message: error.message })}\n\n`);
    }
  };

  // Send an immediate update
  sendStatus();

  // Set up a polling interval (every 2 seconds in this example)
  const intervalId = setInterval(sendStatus, 500);

  // Clean up on client disconnect
  req.on("close", () => {
    clearInterval(intervalId);
    res.end();
  });
});

module.exports = router;
