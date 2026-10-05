// =========================================
// ARPSHIELD DASHBOARD
// =========================================

async function loadDashboardOverview() {

    try {

        const response = await fetch("/api/dashboard/overview");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        updateMetrics(data);
        updateAlerts(data);

    } catch (error) {

        console.error(
            "Failed to load ARPShield dashboard data:",
            error
        );

    }
}


// =========================================
// UPDATE METRIC CARDS
// =========================================

function updateMetrics(data) {

    const totalDevices =
        data.devices?.total ?? 0;

    const suspiciousDevices =
        data.devices?.suspicious ?? 0;

    const openIncidents =
        data.security?.open_incidents ?? 0;

    const arpPackets =
        data.arp?.total_packets ?? 0;


    const deviceElement =
        document.getElementById("metric-devices");

    const threatElement =
        document.getElementById("metric-threats");

    const arpElement =
        document.getElementById("metric-arp");


    if (deviceElement) {
        deviceElement.textContent = totalDevices;
    }

    if (threatElement) {
        threatElement.textContent =
            String(suspiciousDevices).padStart(2, "0");
    }

    if (arpElement) {
        arpElement.textContent = arpPackets;
    }


    // Simple health calculation for now.
    //
    // Later we can make this reflect actual
    // detection/impact conditions more accurately.

    let health = 100;

    health -= suspiciousDevices * 10;
    health -= openIncidents * 15;

    health = Math.max(0, Math.min(100, health));


    const healthElement =
        document.getElementById("metric-health");

    if (healthElement) {
        healthElement.textContent = `${health}%`;
    }
}


// =========================================
// UPDATE SECURITY EVENTS
// =========================================

function updateAlerts(data) {

    const container =
        document.getElementById("security-events");

    if (!container) {
        return;
    }


    const alerts =
        data.recent_alerts ?? [];


    if (alerts.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">✓</span>

                <div>
                    <div class="empty-title">
                        NO ACTIVE SECURITY EVENTS
                    </div>

                    <div class="empty-description">
                        ARPShield has not recorded any
                        recent security alerts.
                    </div>
                </div>
            </div>
        `;

        return;
    }


    container.innerHTML = alerts.map(alert => {

        const severity =
            (alert.severity || "medium").toLowerCase();


        const time =
            formatTimestamp(alert.timestamp);


        return `
            <div class="event">

                <span class="event-dot ${severity}"></span>

                <div>

                    <div class="event-name">
                        ${escapeHtml(
                            alert.reason ||
                            alert.event_type ||
                            "Security event"
                        )}
                    </div>

                    <div class="event-description">
                        ${escapeHtml(
                            alert.rule ||
                            "RULE_BASED_DETECTION"
                        )}
                    </div>

                </div>

                <span class="event-time">
                    ${time}
                </span>

            </div>
        `;

    }).join("");
}


// =========================================
// TIMESTAMP
// =========================================

function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "--:--";
    }

    try {

        return new Date(timestamp)
            .toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
            });

    } catch {

        return "--:--";
    }
}


// =========================================
// BASIC HTML ESCAPING
// =========================================

function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// =========================================
// LIVE CLOCK
// =========================================

function updateClock() {

    const clock =
        document.getElementById("system-clock");

    if (!clock) {
        return;
    }

    const now = new Date();

    clock.textContent =
        now.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
}

// =========================================
// DEVICE REGISTRY
// =========================================

async function loadDevices() {

    const tableBody =
        document.getElementById("device-table-body");

    const countElement =
        document.getElementById("device-count");

    // This function only runs on the Devices page.
    if (!tableBody) {
        return;
    }

    try {

        const response =
            await fetch("/api/devices/");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data =
            await response.json();

        const devices =
            data.devices ?? [];


        // -----------------------------
        // DEVICE COUNT
        // -----------------------------

        if (countElement) {
            countElement.textContent =
                `${devices.length} DEVICES`;
        }


        // -----------------------------
        // NO DEVICES
        // -----------------------------

        if (devices.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="table-empty">
                            NO DEVICES DETECTED
                        </div>
                    </td>
                </tr>
            `;

            return;
        }


        // -----------------------------
        // RENDER DEVICES
        // -----------------------------

        tableBody.innerHTML =
            devices.map(device => {

                const status =
                    (device.status || "unknown")
                    .toLowerCase();

                const statusClass =
                    ["normal", "suspicious", "isolated"]
                        .includes(status)
                        ? status
                        : "normal";

                const statusLabel =
                    status.toUpperCase();

                const trusted =
                    device.trusted === true;


                return `
                    <tr>

                        <td>
                            <span
                                class="status-badge ${statusClass}"
                            >
                                ● ${escapeHtml(statusLabel)}
                            </span>
                        </td>

                        <td>
                            <span class="device-ip">
                                ${escapeHtml(
                                    device.ip_address || "--"
                                )}
                            </span>
                        </td>

                        <td>
                            <span class="device-mac">
                                ${escapeHtml(
                                    device.mac_address || "--"
                                )}
                            </span>
                        </td>

                        <td>
                            <span class="device-hostname">
                                ${escapeHtml(
                                    device.hostname || "UNKNOWN"
                                )}
                            </span>
                        </td>

                        <td>
                            <span class="${
                                trusted
                                    ? "trusted"
                                    : "untrusted"
                            }">
                                ${
                                    trusted
                                        ? "✓ TRUSTED"
                                        : "— UNTRUSTED"
                                }
                            </span>
                        </td>

                        <td>
                            ${formatTimestamp(
                                device.last_seen
                            )}
                        </td>

                    </tr>
                `;

            }).join("");


    } catch (error) {

        console.error(
            "Failed to load devices:",
            error
        );

        tableBody.innerHTML = `
            <tr>
                <td colspan="6">
                    <div class="table-empty">
                        DEVICE REGISTRY UNAVAILABLE
                    </div>
                </td>
            </tr>
        `;
    }
}

// =========================================
// SECURITY ALERTS
// =========================================

async function loadAlerts() {

    const feed =
        document.getElementById("alert-feed");

    if (!feed) {
        return;
    }

    try {

        const [alertsResponse, summaryResponse] =
            await Promise.all([
                fetch("/api/alerts/"),
                fetch("/api/alerts/summary")
            ]);


        if (!alertsResponse.ok ||
            !summaryResponse.ok) {

            throw new Error("Alert API unavailable");
        }


        const alertData =
            await alertsResponse.json();

        const summaryData =
            await summaryResponse.json();


        const alerts =
            alertData.alerts ?? [];

        const summary =
            summaryData.summary ?? {};


        // -----------------------------
        // SUMMARY
        // -----------------------------

        document.getElementById(
            "critical-count"
        ).textContent =
            summary.critical ?? 0;

        document.getElementById(
            "high-count"
        ).textContent =
            summary.high ?? 0;

        document.getElementById(
            "medium-count"
        ).textContent =
            summary.medium ?? 0;

        document.getElementById(
            "low-count"
        ).textContent =
            summary.low ?? 0;


        document.getElementById(
            "alert-count"
        ).textContent =
            `${alerts.length} ALERTS`;


        // -----------------------------
        // EMPTY
        // -----------------------------

        if (alerts.length === 0) {

            feed.innerHTML = `
                <div class="alert-empty">
                    NO SECURITY ALERTS RECORDED
                </div>
            `;

            return;
        }


        // -----------------------------
        // ALERT FEED
        // -----------------------------

        feed.innerHTML =
            alerts.map(alert => {

                const severity =
                    (
                        alert.severity ||
                        "LOW"
                    ).toLowerCase();


                return `
                    <div class="alert-item">

                        <div>
                            <span
                                class="severity-badge ${severity}"
                            >
                                ${escapeHtml(
                                    severity.toUpperCase()
                                )}
                            </span>
                        </div>


                        <div>

                            <div class="alert-rule">
                                ${escapeHtml(
                                    alert.rule_name ||
                                    "UNKNOWN_RULE"
                                )}
                            </div>

                            <div class="alert-reason">
                                ${escapeHtml(
                                    alert.reason ||
                                    "No reason provided."
                                )}
                            </div>

                        </div>


                        <div class="alert-endpoint">

                            <div class="alert-endpoint-label">
                                SUSPICIOUS HOST
                            </div>

                            ${escapeHtml(
                                alert.suspicious_ip ||
                                alert.suspicious_mac ||
                                "UNKNOWN"
                            )}

                        </div>


                        <div class="alert-time">
                            ${formatTimestamp(
                                alert.timestamp
                            )}
                        </div>

                    </div>
                `;

            }).join("");


    } catch (error) {

        console.error(
            "Failed to load security alerts:",
            error
        );

        feed.innerHTML = `
            <div class="alert-empty">
                SECURITY ALERT FEED UNAVAILABLE
            </div>
        `;
    }
}

// =========================================
// INCIDENT REGISTRY
// =========================================

async function loadIncidents() {

    const container =
        document.getElementById("incident-list");

    if (!container) {
        return;
    }

    try {

        const response =
            await fetch("/api/incidents/");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data =
            await response.json();

        const incidents =
            data.incidents ?? [];


        const countElement =
            document.getElementById("incident-count");

        if (countElement) {
            countElement.textContent =
                `${incidents.length} INCIDENTS`;
        }


        if (incidents.length === 0) {

            container.innerHTML = `
                <div class="alert-empty">
                    NO SECURITY INCIDENTS RECORDED
                </div>
            `;

            return;
        }


        container.innerHTML =
            incidents.map(incident => {

                const severity =
                    (
                        incident.severity ||
                        "LOW"
                    ).toLowerCase();

                const status =
                    (
                        incident.status ||
                        "OPEN"
                    ).toLowerCase();


                return `
                    <div class="incident-item">

                        <div>
                            <div class="incident-code">
                                ${escapeHtml(
                                    incident.incident_code
                                )}
                            </div>
                        </div>


                        <div>
                            <div class="incident-severity ${severity}">
                                ${escapeHtml(
                                    severity.toUpperCase()
                                )}
                            </div>
                        </div>


                        <div>

                            <div class="incident-title">
                                ${escapeHtml(
                                    incident.title
                                )}
                            </div>

                            <div class="incident-summary">
                                ${escapeHtml(
                                    incident.impact_summary ||
                                    "No impact summary available."
                                )}
                            </div>

                        </div>


                        <div class="incident-attacker">

                            ${escapeHtml(
                                incident.attacker_mac ||
                                "UNKNOWN"
                            )}

                            <div class="incident-target">
                                TARGET:
                                ${escapeHtml(
                                    incident.target_ip ||
                                    "UNKNOWN"
                                )}
                            </div>

                        </div>


                        <div>

                            <span
                                class="incident-status ${status}"
                            >
                                ${escapeHtml(
                                    status.toUpperCase()
                                )}
                            </span>

                            <div class="incident-time">
                                ${formatTimestamp(
                                    incident.created_at
                                )}
                            </div>

                        </div>

                    </div>
                `;

            }).join("");


    } catch (error) {

        console.error(
            "Failed to load incidents:",
            error
        );

        container.innerHTML = `
            <div class="alert-empty">
                INCIDENT REGISTRY UNAVAILABLE
            </div>
        `;
    }
}

// =========================================
// NETWORK IMPACT
// =========================================

let arpRateChart = null;


async function loadImpact() {

    const arpRateElement =
        document.getElementById("impact-arp-rate");

    if (!arpRateElement) {
        return;
    }


    try {

        const response =
            await fetch("/api/impact/");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data =
            await response.json();

        const metrics =
            data.metrics ?? [];


        const latest =
            metrics.length > 0
                ? metrics[0]
                : null;


        // -----------------------------
        // NO DATA
        // -----------------------------

        if (!latest) {

            document.getElementById(
                "impact-arp-rate"
            ).textContent = "0";

            document.getElementById(
                "impact-ratio"
            ).textContent = "0";

            document.getElementById(
                "impact-macs"
            ).textContent = "0";

            document.getElementById(
                "impact-hosts"
            ).textContent = "0";

            document.getElementById(
                "impact-bandwidth"
            ).textContent = "--";

            document.getElementById(
                "impact-timestamp"
            ).textContent = "--";


            const flood =
                document.getElementById(
                    "flood-status"
                );

            flood.classList.remove("detected");

            document.getElementById(
                "flood-status-text"
            ).textContent =
                "NO NETWORK FLOOD DETECTED";

            document.getElementById(
                "impact-sample-count"
            ).textContent =
                "0 SAMPLES";


            renderImpactChart([]);

            return;
        }


        // -----------------------------
        // LATEST METRIC
        // -----------------------------

        document.getElementById(
            "impact-arp-rate"
        ).textContent =
            Number(
                latest.arp_rate_per_sec
            ).toFixed(2);


        document.getElementById(
            "impact-ratio"
        ).textContent =
            Number(
                latest.request_reply_ratio
            ).toFixed(2);


        document.getElementById(
            "impact-macs"
        ).textContent =
            latest.unique_mac_count;


        document.getElementById(
            "impact-hosts"
        ).textContent =
            latest.affected_hosts_count;


        document.getElementById(
            "impact-bandwidth"
        ).textContent =
            latest.bandwidth_kbps != null
                ? `${Number(
                    latest.bandwidth_kbps
                  ).toFixed(2)} KBPS`
                : "--";


        document.getElementById(
            "impact-timestamp"
        ).textContent =
            formatTimestamp(
                latest.timestamp
            );


        // -----------------------------
        // FLOOD STATUS
        // -----------------------------

        const flood =
            document.getElementById(
                "flood-status"
            );

        const floodText =
            document.getElementById(
                "flood-status-text"
            );


        if (latest.flood_detected) {

            flood.classList.add("detected");

            floodText.textContent =
                "NETWORK FLOOD DETECTED";

        } else {

            flood.classList.remove("detected");

            floodText.textContent =
                "NO NETWORK FLOOD DETECTED";
        }


        // -----------------------------
        // CHART
        // -----------------------------

        document.getElementById(
            "impact-sample-count"
        ).textContent =
            `${metrics.length} SAMPLES`;


        renderImpactChart(
            [...metrics].reverse()
        );


    } catch (error) {

        console.error(
            "Failed to load network impact:",
            error
        );
    }
}


function renderImpactChart(metrics) {

    const canvas =
        document.getElementById(
            "arp-rate-chart"
        );

    if (!canvas || typeof Chart === "undefined") {
        return;
    }


    const labels =
        metrics.map(metric =>
            formatTimestamp(
                metric.timestamp
            )
        );


    const values =
        metrics.map(metric =>
            Number(
                metric.arp_rate_per_sec
            )
        );


    if (arpRateChart) {
        arpRateChart.destroy();
    }


    arpRateChart = new Chart(
        canvas,
        {
            type: "line",

            data: {
                labels: labels,

                datasets: [
                    {
                        label: "ARP packets/sec",

                        data: values,

                        tension: 0.25,

                        pointRadius: 2
                    }
                ]
            },

            options: {
                responsive: true,

                maintainAspectRatio: false,

                plugins: {
                    legend: {
                        display: false
                    }
                },

                scales: {
                    x: {
                        ticks: {
                            color: "#66727f",

                            font: {
                                family:
                                    "monospace",

                                size: 8
                            }
                        },

                        grid: {
                            color:
                                "rgba(255,255,255,0.04)"
                        }
                    },

                    y: {
                        beginAtZero: true,

                        ticks: {
                            color: "#66727f",

                            font: {
                                family:
                                    "monospace",

                                size: 8
                            }
                        },

                        grid: {
                            color:
                                "rgba(255,255,255,0.04)"
                        }
                    }
                }
            }
        }
    );
}

// =========================================
// MITIGATION REQUESTS
// =========================================

async function loadMitigation() {

    const container =
        document.getElementById("mitigation-list");

    if (!container) {
        return;
    }

    try {

        const response =
            await fetch("/api/mitigation/");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data =
            await response.json();

        const requests =
            data.requests ?? [];


        const countElement =
            document.getElementById(
                "mitigation-count"
            );

        if (countElement) {
            countElement.textContent =
                `${requests.length} REQUESTS`;
        }


        if (requests.length === 0) {

            container.innerHTML = `
                <div class="alert-empty">
                    NO MITIGATION REQUESTS RECORDED
                </div>
            `;

            return;
        }


        container.innerHTML =
            requests.map(item => {

                const status =
                    (
                        item.status ||
                        "PENDING"
                    ).toLowerCase();


                return `
                    <div class="mitigation-item">

                        <div class="mitigation-code">
                            ${escapeHtml(
                                item.request_code
                            )}
                        </div>


                        <div>

                            <div class="mitigation-action">
                                ${escapeHtml(
                                    item.action_type
                                )}
                            </div>

                            <div class="mitigation-target">
                                TARGET:
                                ${escapeHtml(
                                    item.target_ip ||
                                    item.target_mac ||
                                    "UNKNOWN"
                                )}
                            </div>

                        </div>


                        <div class="mitigation-reason">
                            ${escapeHtml(
                                item.reason ||
                                "No reason provided."
                            )}
                        </div>


                        <div>

                            <span
                                class="mitigation-status ${status}"
                            >
                                ${escapeHtml(
                                    status.toUpperCase()
                                )}
                            </span>

                        </div>


                        <div class="mitigation-time">
                            ${formatTimestamp(
                                item.created_at
                            )}
                        </div>

                    </div>
                `;

            }).join("");


    } catch (error) {

        console.error(
            "Failed to load mitigation requests:",
            error
        );

        container.innerHTML = `
            <div class="alert-empty">
                MITIGATION SERVICE UNAVAILABLE
            </div>
        `;
    }
}

// =========================================
// RECOVERY MONITORING
// =========================================

async function loadRecovery() {

    const statusElement =
        document.getElementById("recovery-status");

    if (!statusElement) {
        return;
    }

    try {

        const response =
            await fetch("/api/recovery/");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data =
            await response.json();

        const logs =
            data.logs ?? [];

        const countElement =
            document.getElementById("recovery-count");

        if (countElement) {
            countElement.textContent =
                `${logs.length} LOGS`;
        }


        // -----------------------------
        // NO DATA
        // -----------------------------

        if (logs.length === 0) {

            statusElement.textContent =
                "NO DATA";

            document.getElementById(
                "recovery-detail"
            ).textContent =
                "No recovery telemetry has been recorded.";

            setRecoveryCheck(
                "arp-cache-check",
                "arp-cache-status",
                null
            );

            setRecoveryCheck(
                "gateway-check",
                "gateway-status",
                null
            );

            setRecoveryCheck(
                "traffic-check",
                "traffic-status",
                null
            );

            renderRecoveryHistory([]);

            return;
        }


        const latest = logs[0];


        // -----------------------------
        // CURRENT STATUS
        // -----------------------------

        const recoveryStatus =
            (
                latest.recovery_status ||
                "MONITORING"
            ).toLowerCase();


        const statusCard =
            document.getElementById(
                "recovery-status-card"
            );

        statusCard.classList.remove(
            "restored",
            "unstable",
            "monitoring"
        );

        statusCard.classList.add(
            recoveryStatus
        );


        statusElement.textContent =
            recoveryStatus.toUpperCase();


        document.getElementById(
            "recovery-detail"
        ).textContent =
            latest.details ||
            "Latest recovery telemetry received.";


        // -----------------------------
        // HEALTH CHECKS
        // -----------------------------

        setRecoveryCheck(
            "arp-cache-check",
            "arp-cache-status",
            latest.arp_cache_healthy
        );

        setRecoveryCheck(
            "gateway-check",
            "gateway-status",
            latest.gateway_reachable
        );

        setRecoveryCheck(
            "traffic-check",
            "traffic-status",
            latest.traffic_normalized
        );


        renderRecoveryHistory(logs);


    } catch (error) {

        console.error(
            "Failed to load recovery telemetry:",
            error
        );

        statusElement.textContent =
            "UNAVAILABLE";
    }
}


function setRecoveryCheck(
    cardId,
    valueId,
    healthy
) {

    const card =
        document.getElementById(cardId);

    const value =
        document.getElementById(valueId);


    card.classList.remove(
        "healthy",
        "unhealthy"
    );


    if (healthy === null) {

        value.textContent = "--";

        return;
    }


    if (healthy) {

        card.classList.add(
            "healthy"
        );

        value.textContent =
            "HEALTHY";

    } else {

        card.classList.add(
            "unhealthy"
        );

        value.textContent =
            "UNHEALTHY";
    }
}


function renderRecoveryHistory(logs) {

    const container =
        document.getElementById(
            "recovery-list"
        );

    if (!container) {
        return;
    }


    container.innerHTML =
        logs.map(log => {

            const status =
                (
                    log.recovery_status ||
                    "MONITORING"
                ).toLowerCase();


            return `
                <div class="recovery-item">

                    <div class="recovery-target">

                        ${escapeHtml(
                            log.target_mac ||
                            "UNKNOWN"
                        )}

                        <div class="recovery-target-detail">

                            IP:
                            ${escapeHtml(
                                log.target_ip ||
                                "UNKNOWN"
                            )}

                        </div>

                    </div>


                    <div>

                        <span
                            class="recovery-state ${status}"
                        >
                            ${escapeHtml(
                                status.toUpperCase()
                            )}
                        </span>

                    </div>


                    <div class="recovery-check-summary">

                        <div class="${
                            log.arp_cache_healthy
                                ? "healthy"
                                : "unhealthy"
                        }">
                            ARP CACHE:
                            ${
                                log.arp_cache_healthy
                                    ? "HEALTHY"
                                    : "UNHEALTHY"
                            }
                        </div>

                        <div class="${
                            log.gateway_reachable
                                ? "healthy"
                                : "unhealthy"
                        }">
                            GATEWAY:
                            ${
                                log.gateway_reachable
                                    ? "REACHABLE"
                                    : "UNREACHABLE"
                            }
                        </div>

                        <div class="${
                            log.traffic_normalized
                                ? "healthy"
                                : "unhealthy"
                        }">
                            TRAFFIC:
                            ${
                                log.traffic_normalized
                                    ? "NORMAL"
                                    : "ABNORMAL"
                            }
                        </div>

                    </div>


                    <div>
                        ${escapeHtml(
                            log.details ||
                            "No details."
                        )}
                    </div>


                    <div class="recovery-time">

                        ${formatTimestamp(
                            log.timestamp
                        )}

                    </div>

                </div>
            `;

        }).join("");
}

// =========================================
// INITIALIZATION
// =========================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        updateClock();

        setInterval(
            updateClock,
            1000
        );


        // Overview data

        loadDashboardOverview();

        setInterval(
            loadDashboardOverview,
            5000
        );


        // Device registry

        loadDevices();

        setInterval(
            loadDevices,
            5000
        );

        // Security alerts

        loadAlerts();

        setInterval(
            loadAlerts,
            5000
        );

        // Incident registry

        loadIncidents();

        setInterval(
            loadIncidents,
            5000
        );

        // Network impact

        loadImpact();

        setInterval(
            loadImpact,
            5000
        );

        // Mitigation requests

        loadMitigation();

        setInterval(
            loadMitigation,
            5000
        );

        loadRecovery();

        setInterval(
            loadRecovery,
            5000
        );

    }
);