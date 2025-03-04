const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();
const authenticateJWT = require("../middlewares/authenticateJWT");

// Route pour récupérer les quotas et l'utilisation réelle
router.get("/", authenticateJWT, async (req, res) => {
    try {
        const projectId = req.user.project_id;
        if (!projectId) {
            return res.status(400).json({ error: "Aucun projet associé à cet utilisateur." });
        }

        // 🔑 Obtenir un token OpenStack
        const authResponse = await axios.post(`${process.env.OS_IDENTITY_URL}/auth/tokens`, {
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
                scope: { project: { id: projectId } },
            },
        });

        const keystoneToken = authResponse.headers["x-subject-token"];
        if (!keystoneToken) {
            return res.status(401).json({ error: "Impossible d'obtenir un token OpenStack." });
        }

        // 📌 Récupérer les quotas alloués (Compute & Network)
        const [quotasResponse, networkQuotasResponse] = await Promise.all([
            axios.get(`${process.env.OS_NOVA_URL}/os-quota-sets/${projectId}`, { 
                headers: { "X-Auth-Token": keystoneToken } 
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/quotas/${projectId}`, { 
                headers: { "X-Auth-Token": keystoneToken } 
            })
        ]);

        // 📌 Récupérer les ressources utilisées (Compute)
        const usageResponse = await axios.get(`${process.env.OS_NOVA_URL}/limits`, {
            headers: { "X-Auth-Token": keystoneToken }
        });

        // 📌 Récupérer les ressources utilisées (Neutron)
        const [floatingIpsResponse, networksResponse, portsResponse, routersResponse, securityGroupsResponse, securityGroupRulesResponse] = await Promise.all([
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/floatingips?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/networks?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/ports?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/routers?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/security-groups?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            }),
            axios.get(`${process.env.OS_NEUTRON_URL}/v2.0/security-group-rules?project_id=${projectId}`, {
                headers: { "X-Auth-Token": keystoneToken }
            })
        ]);

        const computeQuotas = quotasResponse.data.quota_set;
        const networkQuotas = networkQuotasResponse.data.quota;
        const computeUsage = usageResponse.data.limits.absolute;

        // 📌 Construire un objet propre avec les données
        const quotas = {
            compute: {
                instances: {
                    used: computeUsage.totalInstancesUsed,
                    total: computeQuotas.instances,
                },
                cores: {
                    used: computeUsage.totalCoresUsed,
                    total: computeQuotas.cores,
                },
                ram: {
                    used: computeUsage.totalRAMUsed,
                    total: computeQuotas.ram,
                },
            },
            network: {
                floatingip: {
                    used: floatingIpsResponse.data.floatingips.length,
                    total: networkQuotas.floatingip,
                },
                security_group: {
                    used: securityGroupsResponse.data.security_groups.length,
                    total: networkQuotas.security_group,
                },
                security_group_rule: {
                    used: securityGroupRulesResponse.data.security_group_rules.length,
                    total: networkQuotas.security_group_rule,
                },
                network: {
                    used: networksResponse.data.networks.length,
                    total: networkQuotas.network,
                },
                port: {
                    used: portsResponse.data.ports.length,
                    total: networkQuotas.port,
                },
                router: {
                    used: routersResponse.data.routers.length,
                    total: networkQuotas.router,
                },
            },
        };

        res.json(quotas);
    } catch (error) {
        console.error("Erreur lors de la récupération des quotas :", error);
        res.status(500).json({ error: "Erreur lors de la récupération des quotas." });
    }
});

module.exports = router;
