const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();
const { pool } = require("../db");
const authenticateJWT = require("../middlewares/authenticateJWT");

router.post("/create-project", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { name, description, allocatedResources, pack } = req.body;

  try {
    // Step 1: Obtain a Keystone token using admin credentials
    const authPayload = {
      auth: {
        identity: {
          methods: ["password"],
          password: {
            user: {
              name: process.env.OS_USERNAME,
              domain: { id: process.env.OS_DOMAIN_ID },
              password: process.env.OS_PASSWORD,
            },
          },
        },
        scope: {
          project: {
            name: process.env.OS_PROJECT_NAME,
            domain: { id: process.env.OS_DOMAIN_ID },
          },
        },
      },
    };

    const authResponse = await axios.post(
      `${process.env.OS_IDENTITY_URL}/auth/tokens`,
      authPayload,
      { headers: { "Content-Type": "application/json" } }
    );

    const keystoneToken = authResponse.headers["x-subject-token"];
    if (!keystoneToken) {
      return res.status(401).json({ error: "Failed to get Keystone token" });
    }

    // Step 2: Create a new project in Keystone
    const projectPayload = {
      project: {
        name: name,
        description: description,
        enabled: true,
      },
    };

    const createResponse = await axios.post(
      `${process.env.OS_IDENTITY_URL}/projects`,
      projectPayload,
      {
        headers: {
          "X-Auth-Token": keystoneToken,
          "Content-Type": "application/json",
        },
      }
    );

    const projectId = createResponse.data.project.id;
    if (!projectId) {
      return res.status(500).json({ error: "Project creation failed" });
    }

    console.log(` Project Created: ${projectId}`);

    // Step 3: Get "Member" and "Admin" Role IDs
    const rolesResponse = await axios.get(
      `${process.env.OS_IDENTITY_URL}/roles`,
      {
        headers: {
          "X-Auth-Token": keystoneToken,
          "Content-Type": "application/json",
        },
      }
    );

    const memberRole = rolesResponse.data.roles.find(
      (role) => role.name.toLowerCase() === "member"
    );

    const adminRole = rolesResponse.data.roles.find(
      (role) => role.name.toLowerCase() === "admin"
    );

    if (!memberRole || !adminRole) {
      return res.status(500).json({ error: "Roles not found" });
    }

    const memberRoleId = memberRole.id;
    const adminRoleId = adminRole.id;
    console.log(`🎭 Found Roles -> Member: ${memberRoleId}, Admin: ${adminRoleId}`);

    // Step 4: Fetch **ALL USERS** in OpenStack
    const usersResponse = await axios.get(
      `${process.env.OS_IDENTITY_URL}/users`,
      {
        headers: {
          "X-Auth-Token": keystoneToken,
          "Content-Type": "application/json",
        },
      }
    );

    const users = usersResponse.data.users;
    console.log(` Total Users Fetched: ${users.length}`);

    // Step 5: Assign "Member" and "Admin" Role to Each User
    console.log(` Adding Users to Project: ${projectId}`);
    for (const user of users) {
      try {
        // Assign Member Role
        await axios.put(
          `${process.env.OS_IDENTITY_URL}/projects/${projectId}/users/${user.id}/roles/${memberRoleId}`,
          {},  // Send an empty JSON object instead of null
          {
            headers: {
              "X-Auth-Token": keystoneToken,
              "Content-Type": "application/json",
            },
          }
        );
        console.log(` Added User ${user.name} as Member to Project ${projectId}`);

        // Assign Admin Role
        await axios.put(
          `${process.env.OS_IDENTITY_URL}/projects/${projectId}/users/${user.id}/roles/${adminRoleId}`,
          {},  // Send an empty JSON object instead of null
          {
            headers: {
              "X-Auth-Token": keystoneToken,
              "Content-Type": "application/json",
            },
          }
        );
        console.log(` Added User ${user.name} as Admin to Project ${projectId}`);

      } catch (error) {
        console.error(` Error adding user ${user.name}:`, error.response ? error.response.data : error.message);
      }
    }

    // Step 6: Update Project Quotas in Nova
    const quotaPayload = {
      quota_set: {
        ram: parseInt(allocatedResources.ram, 10),
        cores: parseInt(allocatedResources.vcpus, 10),
      },
    };

    await axios.put(
      `${process.env.OS_NOVA_URL}/os-quota-sets/${projectId}?force=true`,
      quotaPayload,
      {
        headers: {
          "X-Auth-Token": keystoneToken,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(" Quotas Updated Successfully!");

    // Step 7: Store Project ID in the Database
    let updateQuery = "";
    if (pack === "eco") {
      updateQuery = "UPDATE users SET eco = 1, project_id = ? WHERE id = ?";
    } else if (pack === "duo") {
      updateQuery = "UPDATE users SET duo = 1, project_id = ? WHERE id = ?";
    } else if (pack === "trio") {
      updateQuery = "UPDATE users SET trio = 1, project_id = ? WHERE id = ?";
    } else if (pack === "flex") {
      updateQuery = "UPDATE users SET flex = 1, project_id = ? WHERE id = ?";
    } else {
      updateQuery = "UPDATE users SET project_id = ? WHERE id = ?";
    }
    await pool.query(updateQuery, [projectId, userId]);

    res.status(201).json({
      message: " Project created, resources allocated, all users added as Members & Admins.",
      projectId,
    });

  } catch (error) {
    console.error(
      " Error creating project:",
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ error: "Failed to create project" });
  }
});

module.exports = router;



router.post("/update-project", authenticateJWT, async (req, res) => {
  const userId = req.user.id;

  const { allocatedResources, pack } = req.body;
  try {
    // Get the current project_id for this user from the database
    const [rows] = await pool.query(
      "SELECT project_id FROM users WHERE id = ?",
      [userId]
    );
    if (rows.length === 0 || !rows[0].project_id) {
      return res
        .status(404)
        .json({ error: "User does not have an existing project." });
    }
    const projectId = rows[0].project_id;

    // Obtain a Keystone token using admin credentials (to update quotas)
    const authPayload = {
      auth: {
        identity: {
          methods: ["password"],
          password: {
            user: {
              name: process.env.OS_USERNAME,
              domain: { id: process.env.OS_DOMAIN_ID },
              password: process.env.OS_PASSWORD,
            },
          },
        },
        scope: {
          project: {
            id: projectId,
          },
        },
      },
    };

    const authResponse = await axios.post(
      `${process.env.OS_IDENTITY_URL}/auth/tokens`,
      authPayload,
      { headers: { "Content-Type": "application/json" } }
    );
    const keystoneToken = authResponse.headers["x-subject-token"];
    if (!keystoneToken) {
      return res.status(401).json({ error: "Failed to get Keystone token" });
    }

    // Build the quota update payload with the allocated resources.
    const quotaPayload = {
      quota_set: {
        ram: allocatedResources.ram, // in MB
        cores: allocatedResources.vcpus, // number of vCPUs
        // ephemeral: allocatedResources.disk       // disk quota (GB, ephemeral storage, etc.)
      },
    };

    // Update the quota set for the existing project in Nova.
    await axios.put(
      `${process.env.OS_NOVA_URL}/os-quota-sets/${projectId}?force=true`,
      quotaPayload,
      {
        headers: {
          "X-Auth-Token": keystoneToken,
          "Content-Type": "application/json",
        },
      }
    );

    // Update the user's record in your database to set the pack flag.
    let updateQuery = "";
    if (pack === "eco") {
      updateQuery = "UPDATE users SET eco = 1 WHERE id = ?";
    } else if (pack === "duo") {
      updateQuery = "UPDATE users SET duo = 1 WHERE id = ?";
    } else if (pack === "trio") {
      updateQuery = "UPDATE users SET trio = 1 WHERE id = ?";
    } else if (pack === "flex") {
      updateQuery = "UPDATE users SET flex = 1 WHERE id = ?";
    } else {
      // If pack type is not recognized, do nothing (or you could choose a default behavior)
      return res.status(400).json({ error: "Invalid pack type" });
    }
    await pool.query(updateQuery, [userId]);

    res
      .status(200)
      .json({ message: "Project updated and pack set accordingly", projectId });
  } catch (error) {
    console.error(
      "Error updating project:",
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ error: "Failed to update project" });
  }
});

module.exports = router;
