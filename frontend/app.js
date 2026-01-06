document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const btnHotspotToggle = document.getElementById('btn-hotspot-toggle');
  const btnSnifferToggle = document.getElementById('btn-sniffer-toggle');
  const btnApplyFilters = document.getElementById('btn-apply-filters');
  const btnSearch = document.getElementById('btn-search');
  const searchInput = document.getElementById('search-input');
  const filterMac = document.getElementById('filter-mac');
  const filterIp = document.getElementById('filter-ip');
  const checkSimulation = document.getElementById('check-simulation');
  const packetBody = document.getElementById('packet-body');
  const insightsContainer = document.getElementById('insights-container');
  const appStatus = document.getElementById('app-status');
  const dnsRulesList = document.getElementById('dns-rules-list');

  // DNS Modal Elements
  const dnsModal = document.getElementById('dns-modal');
  const dnsTargetIpInput = document.getElementById('dns-target-ip');
  const dnsDomainInput = document.getElementById('dns-domain');
  const dnsSpoofIpInput = document.getElementById('dns-spoof-ip');
  const btnSaveDnsRule = document.getElementById('btn-save-dns-rule');

  let snifferRunning = false;
  let hotspotRunning = false;

  // Fetch initial status
  async function updateStatus() {
    try {
      const resp = await fetch('/api/status');
      const status = await resp.json();

      snifferRunning = status.sniffer_running;
      hotspotRunning = status.hotspot_running;

      btnSnifferToggle.textContent = snifferRunning ? 'Stop Sniffer' : 'Start Sniffer';
      btnSnifferToggle.className = snifferRunning ? 'btn btn-danger' : 'btn btn-secondary';

      btnHotspotToggle.textContent = hotspotRunning ? 'Stop Hotspot' : 'Start Hotspot';
      btnHotspotToggle.className = hotspotRunning ? 'btn btn-danger' : 'btn btn-primary';

      if (snifferRunning || hotspotRunning) {
        appStatus.textContent = 'Online';
        appStatus.className = 'status-badge online';
      } else {
        appStatus.textContent = 'Offline';
        appStatus.className = 'status-badge';
      }
    } catch (e) {
      console.error("Failed to fetch status", e);
    }
  }

  // Fetch and display packets
  async function fetchPackets() {
    const query = searchInput.value;
    const mac = filterMac.value;
    const ip = filterIp.value;

    let url = `/api/packets?`;
    if (query) url += `query=${encodeURIComponent(query)}&`;
    if (mac) url += `mac=${encodeURIComponent(mac)}&`;
    if (ip) url += `ip=${encodeURIComponent(ip)}&`;

    try {
      const resp = await fetch(url);
      const packets = await resp.json();
      renderPackets(packets);
      renderInsights(packets);
    } catch (e) {
      console.error("Failed to fetch packets", e);
    }
  }

  function renderPackets(packets) {
    packetBody.innerHTML = '';
    packets.forEach(p => {
      const row = document.createElement('tr');
      const isDNS = p.analysis_tags && p.analysis_tags.dns_query;
      const isSpoofed = p.analysis_tags && p.analysis_tags.spoofed;

      let payloadSnippet = p.payload.substring(0, 50);
      if (p.payload.length > 50) payloadSnippet += '...';

      let packetType = 'TCP'; // Default
      if (p.payload.includes('DNS Query')) packetType = 'DNS';
      else if (p.payload.startsWith('GET ') || p.payload.startsWith('POST ')) packetType = 'HTTP';
      else if (p.analysis_tags && p.analysis_tags.dns_query) packetType = 'DNS';

      if (isDNS) {
        payloadSnippet = `<strong>${p.analysis_tags.dns_query[0]}</strong>`;
        if (isSpoofed) {
          payloadSnippet += ` <span class="badge-spoofed">SPOOFED</span>`;
        } else {
          payloadSnippet += ` <button class="btn btn-spoof">Spoof</button>`;
        }
      }

      row.innerHTML = `
                <td>${new Date(p.timestamp).toLocaleTimeString()}</td>
                <td>${p.src_mac}</td>
                <td>${p.src_ip}</td>
                <td><span class="type-badge ${packetType.toLowerCase()}">${packetType}</span></td>
                <td>${p.dst_ip}</td>
                <td>${payloadSnippet}</td>
            `;

      const spoofBtn = row.querySelector('.btn-spoof');
      if (spoofBtn) {
        spoofBtn.onclick = (e) => {
          e.stopPropagation();
          openDnsModal(p.src_ip, p.analysis_tags.dns_query[0]);
        };
      }

      row.onclick = () => showPacketDetails(p);
      packetBody.appendChild(row);
    });
  }

  function renderInsights(packets) {
    const allInsights = [];
    packets.forEach(p => {
      if (p.analysis_tags) {
        Object.entries(p.analysis_tags).forEach(([type, values]) => {
          values.forEach(v => {
            allInsights.push({ type, value: v, src: p.src_ip });
          });
        });
      }
    });

    // Deduplicate and limit
    const uniqueInsights = Array.from(new Set(allInsights.map(i => JSON.stringify(i)))).map(s => JSON.parse(s));

    if (uniqueInsights.length === 0) {
      insightsContainer.innerHTML = '<div class="insight-placeholder">Waiting for traffic...</div>';
      return;
    }

    insightsContainer.innerHTML = '';
    uniqueInsights.slice(0, 20).forEach(i => {
      const card = document.createElement('div');
      card.className = 'insight-card';
      card.innerHTML = `
                <h4>${i.type.toUpperCase()} - From ${i.src}</h4>
                <p>${i.value}</p>
            `;
      insightsContainer.appendChild(card);
    });
  }

  function showPacketDetails(p) {
    const modal = document.getElementById('packet-modal');
    const details = document.getElementById('modal-details');
    details.innerHTML = `
            <p><strong>Timestamp:</strong> ${p.timestamp}</p>
            <p><strong>Source MAC:</strong> ${p.src_mac}</p>
            <p><strong>Source IP:</strong> ${p.src_ip}</p>
            <p><strong>Dest IP:</strong> ${p.dst_ip}</p>
            <hr style="margin: 1rem 0; opacity: 0.1">
            <p><strong>Payload:</strong></p>
            <pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 8px; font-family: monospace; white-space: pre-wrap; word-break: break-all;">${p.payload}</pre>
        `;
    modal.style.display = "block";
  }

  function openDnsModal(targetIp, domain) {
    dnsTargetIpInput.value = targetIp;
    dnsDomainInput.value = domain;
    dnsSpoofIpInput.value = '';
    dnsModal.style.display = 'block';
  }

  btnSaveDnsRule.onclick = async () => {
    const rule = {
      target_ip: dnsTargetIpInput.value,
      domain: dnsDomainInput.value,
      spoof_ip: dnsSpoofIpInput.value
    };

    if (!rule.spoof_ip) {
      alert("Please enter a redirect IP");
      return;
    }

    try {
      await fetch('/api/dns/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule)
      });
      dnsModal.style.display = 'none';
      fetchDnsRules();
    } catch (e) {
      console.error("Failed to save DNS rule", e);
    }
  };

  async function fetchDnsRules() {
    try {
      const resp = await fetch('/api/dns/rules');
      const rules = await resp.json();
      renderDnsRules(rules);
    } catch (e) {
      console.error("Failed to fetch DNS rules", e);
    }
  }

  function renderDnsRules(rules) {
    if (rules.length === 0) {
      dnsRulesList.innerHTML = '<div class="empty-rules">No active rules</div>';
      return;
    }

    dnsRulesList.innerHTML = '';
    rules.forEach(rule => {
      const div = document.createElement('div');
      div.className = 'rule-item';
      div.innerHTML = `
                <span class="domain">${rule.domain}</span>
                <span class="details">${rule.target_ip} &rarr; ${rule.spoof_ip}</span>
                <button class="btn-remove-rule">&times;</button>
            `;
      div.querySelector('.btn-remove-rule').onclick = () => removeDnsRule(rule.target_ip, rule.domain);
      dnsRulesList.appendChild(div);
    });
  }

  async function removeDnsRule(ip, domain) {
    try {
      await fetch(`/api/dns/rules?target_ip=${ip}&domain=${domain}`, {
        method: 'DELETE'
      });
      fetchDnsRules();
    } catch (e) {
      console.error("Failed to remove DNS rule", e);
    }
  }

  // Modal close
  document.getElementById('close-packet-modal').onclick = () => {
    document.getElementById('packet-modal').style.display = "none";
  };

  document.getElementById('close-dns-modal').onclick = () => {
    document.getElementById('dns-modal').style.display = "none";
  };

  // Event Listeners
  btnSnifferToggle.onclick = async () => {
    const action = snifferRunning ? 'stop' : 'start';
    const sim = checkSimulation.checked;
    const url = `/api/control/sniffer/${action}` + (action === 'start' ? `?simulation=${sim}` : '');
    await fetch(url, { method: 'POST' });
    updateStatus();
  };

  btnHotspotToggle.onclick = async () => {
    const action = hotspotRunning ? 'stop' : 'start';
    await fetch(`/api/control/hotspot/${action}`, { method: 'POST' });
    updateStatus();
  };

  btnSearch.onclick = fetchPackets;
  btnApplyFilters.onclick = fetchPackets;

  // Polling
  setInterval(updateStatus, 3000);
  setInterval(fetchPackets, 2000);
  setInterval(fetchDnsRules, 5000);

  updateStatus();
  fetchPackets();
  fetchDnsRules();
});
