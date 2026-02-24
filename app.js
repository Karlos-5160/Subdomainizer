document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const domainInput = document.getElementById('domain-input');
    const scanBtn = document.getElementById('scan-btn');
    const advancedToggle = document.getElementById('advanced-toggle');
    const configPanel = document.getElementById('config-panel');
    const terminalOutput = document.getElementById('terminal-output');
    const resultsSection = document.getElementById('results-section');
    const resultsBody = document.getElementById('results-body');
    const resultCount = document.getElementById('result-count');
    const exportBtn = document.getElementById('export-btn');

    // Config Elements
    const sourceCrtSh = document.getElementById('source-crtsh');
    const sourceWayback = document.getElementById('source-wayback');
    const sourceVt = document.getElementById('source-vt');
    const sourceOtx = document.getElementById('source-otx');
    const sourceHackertarget = document.getElementById('source-hackertarget');
    const sourceMerkleMap = document.getElementById('source-merklemap');
    const sourceRapidDns = document.getElementById('source-rapiddns');
    const sourceC99 = document.getElementById('source-c99');
    const sourceNetcraft = document.getElementById('source-netcraft');
    const sourceNMMapper = document.getElementById('source-nmmapper');
    const sourceHunter = document.getElementById('source-hunter');
    const sourceCensys = document.getElementById('source-censys');
    const sourceFofa = document.getElementById('source-fofa');
    const sourceZoomEye = document.getElementById('source-zoomeye');

    // Credentials
    const vtApiKeyInput = document.getElementById('vt-api-key');
    const otxApiKeyInput = document.getElementById('otx-api-key');
    const htApiKeyInput = document.getElementById('ht-api-key');
    const c99ApiKeyInput = document.getElementById('c99-api-key');
    const hunterApiKeyInput = document.getElementById('hunter-api-key');
    const censysApiSecretInput = document.getElementById('censys-api-secret');
    const fofaApiKeyInput = document.getElementById('fofa-api-key');
    const zoomeyeApiKeyInput = document.getElementById('zoomeye-api-key');

    let discoveredSubdomains = [];

    // Background Proxy (Hidden)
    const bgProxyFetch = async (url) => {
        const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(url)}`;
        return fetch(proxyUrl);
    };

    // UI Logic
    advancedToggle.addEventListener('click', () => {
        configPanel.classList.toggle('hidden');
    });

    // Logger
    const log = (message, type = 'info') => {
        const entry = document.createElement('p');
        entry.className = `log-entry ${type}`;
        // Basic link detection
        if (message.includes('http')) {
            entry.innerHTML = `> ${message}`;
        } else {
            entry.textContent = `> ${message}`;
        }
        terminalOutput.appendChild(entry);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    };

    // --- Data Sources ---

    const fetchCrtSh = async (domain) => {
        log(`[CRT.SH] Fetching...`, 'info');
        try {
            const url = `https://crt.sh/?q=${domain}&output=json`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            data.forEach(e => e.name_value.split('\n').forEach(s => {
                if (s.includes(domain) && !s.includes('*')) subs.add(s);
            }));
            log(`[CRT.SH] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[CRT.SH] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchWayback = async (domain) => {
        log(`[WAYBACK] Fetching archive data...`, 'info');
        try {
            const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            if (!data || data.length === 0) return [];

            const subs = new Set();
            for (let i = 1; i < data.length; i++) {
                try {
                    const urlObj = new URL(data[i][0]);
                    if (urlObj.hostname && urlObj.hostname.includes(domain)) {
                        subs.add(urlObj.hostname);
                    }
                } catch (e) { }
            }
            log(`[WAYBACK] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[WAYBACK] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchHackerTarget = async (domain, apiKey) => {
        let msg = apiKey ? `[HACKERTARGET] Fetching (Auth)...` : `[HACKERTARGET] Fetching (Free)...`;
        log(msg, 'info');
        try {
            const url = apiKey ? `https://api.hackertarget.com/hostsearch/?q=${domain}&apikey=${apiKey}` : `https://api.hackertarget.com/hostsearch/?q=${domain}`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const text = await response.text();
            if (text.includes("API count exceeded")) throw new Error("Free Limit Exceeded");
            if (text.includes("error")) throw new Error(text.trim());
            const subs = new Set();
            text.split('\n').forEach(l => {
                const parts = l.split(',');
                if (parts[0] && parts[0].includes(domain)) subs.add(parts[0]);
            });
            log(`[HACKERTARGET] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[HACKERTARGET] Error: ${e.message}. Use API Key or wait.`, 'error');
            return [];
        }
    };

    const fetchMerkleMap = async (domain) => {
        log(`[MERKLEMAP] Fetching...`, 'info');
        try {
            const url = `https://api.merklemap.com/search?query=${domain}`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            if (data.results) {
                data.results.forEach(i => {
                    if (i.domain && i.domain.includes(domain)) subs.add(i.domain);
                });
            }
            log(`[MERKLEMAP] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[MERKLEMAP] Error: ${e.message}`, 'error');
            return [];
        }
    };

    // --- API & Scraper Generators ---

    const logExternalLink = (name, url) => {
        log(`[${name}] Fallback applied. <a href="${url}" target="_blank" style="color: #00ff41; text-decoration: underline;">Click here to view results</a>`, 'info');
        return [];
    };

    const fetchHunter = async (domain, apiKey) => {
        if (!apiKey) return logExternalLink('HUNTER', `https://hunter.how/search?body=${btoa(`domain="${domain}"`)}`);
        log(`[HUNTER] Fetching (API)...`, 'info');
        try {
            const encodedQuery = btoa(`domain="${domain}"`);
            const url = `https://api.hunter.how/search?api-key=${apiKey}&search=${encodedQuery}&page=1&page_size=100`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            if (data.code !== 200) throw new Error(data.message || "API Error");
            const subs = new Set();
            if (data.data && data.data.list) {
                // Hunter typically returns IPs and domains associated with the query
                data.data.list.forEach(item => {
                    if (item.domain && item.domain.includes(domain)) subs.add(item.domain);
                });
            }
            log(`[HUNTER] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[HUNTER] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchCensys = async (domain, apiSecret) => {
        if (!apiSecret) return logExternalLink('CENSYS', `https://search.censys.io/search?resource=hosts&q=${domain}`);
        log(`[CENSYS] Fetching (API)...`, 'info');
        try {
            const url = `https://search.censys.io/api/v2/hosts/search?q=${domain}&per_hits=100`;
            const authStr = btoa(`${apiSecret}`);
            const response = await fetch(url, { headers: { 'Authorization': `Basic ${authStr}`, 'Accept': 'application/json' } });
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            if (data.result && data.result.hits) {
                data.result.hits.forEach(hit => {
                    if (hit.name && hit.name.includes(domain)) subs.add(hit.name);
                    // Check tls names
                    if (hit.services) {
                        hit.services.forEach(svc => {
                            if (svc.tls && svc.tls.certificates && svc.tls.certificates.leaf_data && svc.tls.certificates.leaf_data.names) {
                                svc.tls.certificates.leaf_data.names.forEach(n => {
                                    if (n.includes(domain) && !n.includes('*')) subs.add(n);
                                })
                            }
                        })
                    }
                });
            }
            log(`[CENSYS] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[CENSYS] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchFofa = async (domain, apiKey) => {
        if (!apiKey) return logExternalLink('FOFA', `https://en.fofa.info/result?qbase64=${btoa(`domain="${domain}"`)}`);
        // Fofa API structure usually requires email too, simplifying if key is sufficient or handling error
        log(`[FOFA] Fetching (API)...`, 'info');
        try {
            const qbase64 = btoa(`domain="${domain}"`);
            const url = `https://fofa.info/api/v1/search/all?key=${apiKey}&qbase64=${qbase64}&size=100&fields=host`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            if (data.error) throw new Error("API Error");
            const subs = new Set();
            if (data.results) {
                data.results.forEach(res => {
                    let host = Array.isArray(res) ? res[0] : res;
                    // strip ports/http
                    host = host.replace(/^https?:\/\//, '').split(':')[0];
                    if (host.includes(domain)) subs.add(host);
                });
            }
            log(`[FOFA] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[FOFA] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchZoomEye = async (domain, apiKey) => {
        if (!apiKey) return logExternalLink('ZOOMEYE', `https://www.zoomeye.org/searchResult?q=domain=${domain}`);
        log(`[ZOOMEYE] Fetching (API)...`, 'info');
        try {
            const url = `https://api.zoomeye.org/domain/search?q=${domain}&type=1&page=1`;
            const response = await fetch(url, { headers: { 'API-KEY': apiKey } });
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            if (data.list) {
                data.list.forEach(item => {
                    if (item.name) subs.add(`${item.name}.${domain}`);
                });
            }
            log(`[ZOOMEYE] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[ZOOMEYE] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchNetcraft = async (domain) => {
        log(`[NETCRAFT] Scraping...`, 'info');
        try {
            const url = `https://searchdns.netcraft.com/?restriction=site+contains&host=${domain}`;
            const response = await bgProxyFetch(url);
            if (!response.ok) throw new Error('Proxy returned status ' + response.status);
            const text = await response.text();

            // Look for <a href="http://sub.domain.com"
            const regex = new RegExp(`href="https?:\/\/([a-zA-Z0-9.-]+\\.${domain.replace('.', '\\.')})"`, 'g');
            const subs = new Set();
            let match;
            while ((match = regex.exec(text))) subs.add(match[1]);

            if (subs.size > 0) {
                log(`[NETCRAFT] Found ${subs.size} results.`, 'success');
            } else {
                log(`[NETCRAFT] Found 0 results or BLOCKED by anti-bot.`, 'yellow');
            }
            return Array.from(subs);
        } catch (e) {
            log(`[NETCRAFT] Error/Blocked: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchNMMapper = async (domain) => {
        log(`[NMMAPPER] Scraping...`, 'info');
        try {
            // Usually expects a POST or requires token logic. Trying simple GET request first.
            const url = `https://www.nmmapper.com/tool/subdomainfinder/?q=${domain}`;
            const response = await bgProxyFetch(url);
            if (!response.ok) throw new Error('Proxy returned status ' + response.status);
            const text = await response.text();

            const regex = new RegExp(`>([a-zA-Z0-9.-]+\\.${domain.replace('.', '\\.')})<`, 'g');
            const subs = new Set();
            let match;
            while ((match = regex.exec(text))) subs.add(match[1]);

            if (subs.size > 0) {
                log(`[NMMAPPER] Found ${subs.size} results.`, 'success');
            } else {
                log(`[NMMAPPER] Found 0 results or requires interaction.`, 'yellow');
            }
            return Array.from(subs);
        } catch (e) {
            log(`[NMMAPPER] Error/Blocked: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchRapidDns = async (domain) => {
        log(`[RAPIDDNS] Protected Source. <a href="https://rapiddns.io/subdomain/${domain}?full=1#result" target="_blank" style="color: #00ff41;">View manually</a>`, 'info');
        return [];
    };

    const fetchVirusTotal = async (domain, apiKey) => {
        if (!apiKey) {
            log(`[VIRUSTOTAL] No API Key provided. Attempting UI fetch...`, 'info');
            try {
                // VirusTotal's UI endpoint restricts requests without headers/cookies/CAPTCHA verification. 
                // We use corsproxy to attempt it, but it frequently blocks with reCAPTCHA.
                const url = `https://www.virustotal.com/ui/domains/${domain}/subdomains?limit=40`;
                const response = await bgProxyFetch(url);
                if (!response.ok) throw new Error(`Proxy returned status ${response.status}`);
                const data = await response.json();
                if (data.error && data.error.code === 'RecaptchaRequiredError') throw new Error("Blocked by reCAPTCHA");
                const subs = new Set();
                if (data.data) data.data.forEach(item => subs.add(item.id));
                log(`[VIRUSTOTAL] Found ${subs.size} results (Free UI).`, 'success');
                return Array.from(subs);
            } catch (e) {
                log(`[VIRUSTOTAL] UI Fetch Failed (${e.message}). <a href="https://www.virustotal.com/gui/domain/${domain}/relations" target="_blank" style="color: #00ff41;">View manually</a>`, 'error');
                return [];
            }
        }
        log(`[VIRUSTOTAL] Fetching (API)...`, 'info');
        try {
            const url = `https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=100`;
            const response = await fetch(url, { headers: { 'x-apikey': apiKey } });
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            if (data.data) {
                data.data.forEach(item => subs.add(item.id));
            }
            log(`[VIRUSTOTAL] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[VIRUSTOTAL] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchAlienVault = async (domain, apiKey) => {
        log(`[ALIENVAULT] Fetching...`, 'info');
        try {
            const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
            const headers = apiKey ? { 'X-OTX-API-KEY': apiKey } : {};
            const res = await fetch(url, { headers: headers });
            if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
            const data = await res.json();
            const subs = new Set();
            data.passive_dns.forEach(e => {
                if (e.hostname && e.hostname.includes(domain)) subs.add(e.hostname);
            });
            log(`[ALIENVAULT] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[ALIENVAULT] Error: ${e.message}`, 'error');
            return [];
        }
    };

    const fetchC99 = async (domain, apiKey) => {
        if (!apiKey) {
            log(`[C99] API Key missing. Skipping C99.`, 'error');
            return [];
        }
        log(`[C99] Fetching (API)...`, 'info');
        try {
            // Note: Replace with the actual c99 subdomain scanner endpoint since it might require specific parameters
            const url = `https://api.c99.nl/subdomainscanner?key=${apiKey}&domain=${domain}&json`;
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP Error ${response.status}`);
            const data = await response.json();
            const subs = new Set();
            if (data.success && data.subdomains) {
                data.subdomains.forEach(sub => subs.add(sub.subdomain));
            }
            log(`[C99] Found ${subs.size} results.`, 'success');
            return Array.from(subs);
        } catch (e) {
            log(`[C99] Error: ${e.message}`, 'error');
            return [];
        }
    };

    // --- Main Logic ---

    const renderResults = (subdomains) => {
        resultsBody.innerHTML = '';
        subdomains.sort().forEach((sub, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${String(index + 1).padStart(3, '0')}</td>
                <td><a href="http://${sub}" target="_blank" style="color: inherit; text-decoration: none;">${sub}</a></td>
                <td><span style="color: #00ff41">DETECTED</span></td>
            `;
            resultsBody.appendChild(row);
        });
        resultCount.textContent = subdomains.length;
        resultsSection.classList.remove('hidden');
        void resultsSection.offsetWidth;
        resultsSection.classList.add('visible');
    };

    const handleScan = async () => {
        const domain = domainInput.value.trim();
        if (!domain) {
            log('Please enter a valid domain.', 'error');
            return;
        }

        resultsSection.classList.remove('visible');
        resultsSection.classList.add('hidden');
        resultsBody.innerHTML = '';
        discoveredSubdomains = [];
        terminalOutput.innerHTML = '';

        scanBtn.disabled = true;
        scanBtn.textContent = 'SCANNING...';
        log(`> INITIALIZING SCAN_VECTOR: ${domain}`, 'info');

        const promises = [];

        if (sourceCrtSh.checked) promises.push(fetchCrtSh(domain));
        if (sourceWayback && sourceWayback.checked) promises.push(fetchWayback(domain));
        if (sourceVt.checked) promises.push(fetchVirusTotal(domain, vtApiKeyInput.value.trim()));
        if (sourceOtx.checked) promises.push(fetchAlienVault(domain, otxApiKeyInput.value.trim()));
        if (sourceHackertarget.checked) promises.push(fetchHackerTarget(domain, htApiKeyInput.value.trim()));
        if (sourceMerkleMap.checked) promises.push(fetchMerkleMap(domain));
        if (sourceRapidDns.checked) promises.push(fetchRapidDns(domain));
        if (sourceC99.checked) promises.push(fetchC99(domain, c99ApiKeyInput.value.trim()));

        // Mixed Generators
        if (sourceNetcraft.checked) promises.push(fetchNetcraft(domain));
        if (sourceNMMapper.checked) promises.push(fetchNMMapper(domain));
        if (sourceHunter.checked) promises.push(fetchHunter(domain, hunterApiKeyInput.value.trim()));
        if (sourceCensys.checked) promises.push(fetchCensys(domain, censysApiSecretInput.value.trim()));
        if (sourceFofa.checked) promises.push(fetchFofa(domain, fofaApiKeyInput.value.trim()));
        if (sourceZoomEye.checked) promises.push(fetchZoomEye(domain, zoomeyeApiKeyInput.value.trim()));

        const results = await Promise.allSettled(promises);

        const allSubdomains = new Set();
        results.forEach(result => {
            if (result.status === 'fulfilled' && Array.isArray(result.value)) {
                result.value.forEach(sub => allSubdomains.add(sub));
            }
        });

        discoveredSubdomains = Array.from(allSubdomains);

        if (discoveredSubdomains.length > 0) {
            log(`Scan complete. Unique subdomains: ${discoveredSubdomains.length}`, 'success');
            renderResults(discoveredSubdomains);
        } else {
            log('Scan finished. No fetchable results found. Check external links.', 'yellow');
        }

        scanBtn.disabled = false;
        scanBtn.textContent = 'INITIATE_SCAN';
    };

    const handleExport = () => {
        if (discoveredSubdomains.length === 0) return;
        const csvContent = "data:text/csv;charset=utf-8," + "ID,Subdomain\n" + discoveredSubdomains.map((sub, i) => `${i + 1},${sub}`).join("\n");
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `subdomains_${domainInput.value}_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    scanBtn.addEventListener('click', handleScan);
    domainInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleScan(); });
    exportBtn.addEventListener('click', handleExport);
});
