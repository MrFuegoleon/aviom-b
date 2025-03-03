const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();
const authenticateJWT = require("../middlewares/authenticateJWT");

router.get("/", authenticateJWT, async (req, res) => {
  const projectId = req.user.project_id; // Get project ID from JWT authentication

  if (!projectId) {
    return res.status(400).json({ error: "No project associated with user." });
  }

  try {
    // Step 1: Obtain a Keystone token
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
            id: projectId, // Fetch quotas for the authenticated user's project
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

    // Step 2: Fetch Compute Quotas (Nova)
    const computeQuotaResponse = await axios.get(
      `${process.env.OS_NOVA_URL}/os-quota-sets/${projectId}/detail`,
      {
        headers: { "X-Auth-Token": keystoneToken },
      }
    );

    const computeQuota = computeQuotaResponse.data.quota_set;

    // Step 3: Fetch Network Quotas (Neutron)
    const networkQuotaResponse = await axios.get(
      `${process.env.OS_NEUTRON_URL}/v2.0/quotas/${projectId}`,
      {
        headers: { "X-Auth-Token": keystoneToken },
      }
    );

    const networkQuota = networkQuotaResponse.data.quota;

    // Step 4: Fetch Usage Statistics (to get the "Used" values)
    const usageResponse = await axios.get(
      `${process.env.OS_NOVA_URL}/limits`,
      {
        headers: { "X-Auth-Token": keystoneToken },
      }
    );

    const usage = usageResponse.data.limits.absolute;

    // Step 5: Prepare the quota report
    const quotaReport = {
      compute: {
        instances: { used: usage.totalInstancesUsed, limit: computeQuota.instances.limit },
        vcpus: { used: usage.totalCoresUsed, limit: computeQuota.cores.limit },
        ram: { used: usage.totalRAMUsed, limit: computeQuota.ram.limit / 1024 }, // Convert MB to GB
      },
      network: {
        floating_ips: { used: networkQuota.floatingip, limit: networkQuota.floatingip },
        security_groups: { used: networkQuota.security_group, limit: networkQuota.security_group },
        security_group_rules: { used: networkQuota.security_group_rule, limit: networkQuota.security_group_rule },
        networks: { used: networkQuota.network, limit: networkQuota.network },
        ports: { used: networkQuota.port, limit: networkQuota.port },
        routers: { used: networkQuota.router, limit: networkQuota.router },
      },
    };

    res.status(200).json(quotaReport);
  } catch (error) {
    console.error("Error fetching quotas:", error.response ? error.response.data : error.message);
    res.status(500).json({ error: "Failed to retrieve quotas" });
  }
});

module.exports = router;
