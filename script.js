document.addEventListener('DOMContentLoaded', () => {

    const osintTools = {
        "General Search Engines": [
            { name: "Google", url: "https://www.google.com/search?q=", params: "TARGET" },
            { name: "DuckDuckGo", url: "https://duckduckgo.com/?q=", params: "TARGET" },
            { name: "Bing", url: "https://www.bing.com/search?q=", params: "TARGET" },
            { name: "Yandex", url: "https://yandex.com/search/?text=", params: "TARGET" },
            { name: "Brave Search", url: "https://search.brave.com/search?q=", params: "TARGET" },
            { name: "Startpage", url: "https://www.startpage.com/sp/search?query=", params: "TARGET" },
        ],
        "Domain & IP Intelligence": [
            { name: "ViewDNS (All Tools)", url: "https://viewdns.info/iphistory/?domain=", params: "TARGET" },
            { name: "Who.is", url: "http://who.is/whois/", params: "TARGET" },
            { name: "SecurityTrails", url: "https://securitytrails.com/domain/", params: "TARGET/history" },
            { name: "DNSLytics", url: "https://dnslytics.com/domain/", params: "TARGET" },
            { name: "Robtex", url: "https://www.robtex.com/dns-lookup/", params: "TARGET" },
            { name: "CentralOps", url: "https://centralops.net/co/DomainDossier.aspx?addr=", params: "TARGET&net_whois=true&dom_whois=true" },
            { name: "Whoxy", url: "https://www.whoxy.com/", params: "TARGET" },
            { name: "Whoisology", url: "https://whoisology.com/", params: "TARGET" },
            { name: "ASN Lookup (bgp.he.net)", url: "https://bgp.he.net/search?search%5Bsearch%5D=TARGET&commit=Search", params: "" },
            { name: "GreyNoise (IP)", url: "https://viz.greynoise.io/ip/", params: "TARGET" },
            { name: "AbuseIPDB (IP)", url: "https://www.abuseipdb.com/check/", params: "TARGET" },
        ],
        "Subdomain & DNS Enumeration": [
            { name: "crt.sh", url: "https://crt.sh/?q=%25.", params: "TARGET" },
            { name: "DNSdumpster", url: "https://dnsdumpster.com/?q=", params: "TARGET" },
            { name: "VirusTotal (Relations)", url: "https://www.virustotal.com/gui/domain/", params: "TARGET/relations" },
            { name: "HackerTarget Subdomains", url: "https://hackertarget.com/subdomain-finder/?domain=", params: "TARGET" },
            { name: "Censys (Hosts)", url: "https://search.censys.io/search?resource=hosts&q=", params: "TARGET" },
            { name: "Shodan (Hosts)", url: "https://www.shodan.io/search?query=", params: "TARGET" },
            { name: "Dorki", url: "https://dorki.attaxa.com/search?q=site:", params: "TARGET" },
            { name: "Vedbex", url: "https://www.vedbex.com/tools/subdomain-finder?domain=", params: "TARGET" },
            { name: "Google CT Monitor", url: "https://transparencyreport.google.com/https/certificates?hl=en&search=", params: "TARGET" },
        ],
         "Website Archives & History": [
            { name: "Wayback Machine", url: "http://web.archive.org/web/*/", params: "TARGET" },
            { name: "Archive.today", url: "http://archive.today/search?q=", params: "TARGET" },
            { name: "Google Cache", url: "http://webcache.googleusercontent.com/search?q=cache:", params: "TARGET" },
            { name: "Who.is History", url: "http://who.is/domain-history/", params: "TARGET" },
            { name: "Mementoweb", url: "http://timetravel.mementoweb.org/list/1999/http://", params: "TARGET" },
            { name: "Arquivo.pt", url: "https://arquivo.pt/page/search?hitsPerPage=100&query=site%3A", params: "TARGET" },
        ],
        "Threat Intelligence & Scans": [
            { name: "VirusTotal", url: "https://www.virustotal.com/gui/domain/", params: "TARGET" },
            { name: "URLScan.io", url: "https://urlscan.io/search/#", params: "TARGET" },
            { name: "ThreatCrowd", url: "https://www.threatcrowd.org/domain.php?domain=", params: "TARGET" },
            { name: "ThreatIntel Platform", url: "https://threatintelligenceplatform.com/report/", params: "TARGET" },
            { name: "Blacklight Privacy Scan", url: "https://themarkup.org/blacklight?url=", params: "TARGET" },
            { name: "LeakIX Search", url: "https://leakix.net/search?scope=leak&q=", params: "TARGET" },
            { name: "Spamhaus", url: "https://check.spamhaus.org/search?query=", params: "TARGET" },
            { name: "SSL Labs", url: "https://www.ssllabs.com/ssltest/analyze.html?d=", params: "TARGET" },
            { name: "ViewDNS Port Scan", url: "https://viewdns.info/portscan/?host=", params: "TARGET" },
            { name: "Web-Check.xyz", url: "https://web-check.xyz/check/", params: "TARGET" },
        ],
        "Secrets & Leaks": [
            { name: "Wayback (Sensitive Files)", url: "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$", params: "" },
            { name: "Wayback (.env files)", url: "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.env$", params: "" },
            { name: "Wayback (.js files)", url: "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.js$", params: "" },
            { name: "GitHub Gists (API Keys)", url: "https://gist.github.com/search?q=TARGET+apikey", params: "" },
            { name: "Dehashed", url: "https://dehashed.com/search?query=", params: "TARGET" },
            { name: "HaveIBeenPwned", url: "https://haveibeenpwned.com/account/", params: "TARGET" },
            { name: "IntelligenceX", url: "https://intelx.io/?s=", params: "TARGET" },
            { name: "Skymem", url: "https://www.skymem.info/srch?q=", params: "TARGET" },
        ],
        "Technology Stack & Analytics": [
            { name: "BuiltWith", url: "https://builtwith.com/", params: "TARGET" },
            { name: "Wappalyzer", url: "https://www.wappalyzer.com/lookup/https://", params: "TARGET" },
            { name: "WhatCMS", url: "https://whatcms.org/?s=", params: "TARGET" },
            { name: "PublicWWW (Code Search)", url: "https://publicwww.com/websites/%22", params: "TARGET%22/" },
            { name: "SpyOnWeb (Analytics IDs)", url: "http://spyonweb.com/", params: "TARGET" },
            { name: "Reverse AdSense", url: "https://dnslytics.com/reverse-adsense/", params: "TARGET" },
            { name: "Reverse Analytics", url: "https://dnslytics.com/reverse-analytics/", params: "TARGET" },
        ],
        "Username & People OSINT": [
            { name: "WhatsMyName.app", url: "https://whatsmyname.app/?q=", params: "TARGET" },
            { name: "Sherlock", url: "https://sherlock-project.github.io/?username=", params: "TARGET" },
            { name: "UserSearch.org", url: "https://usersearch.org/index.php?username=", params: "TARGET" },
            { name: "Pipl", url: "https://pipl.com/search/?q=", params: "TARGET" },
            { name: "ThatsThem", url: "https://thatsthem.com/name/", params: "TARGET" },
            { name: "Twitter Search", url: "https://twitter.com/search?q=", params: "TARGET&f=live" },
            { name: "Reddit User", url: "https://www.reddit.com/user/", params: "TARGET" },
            { name: "GitHub User", url: "https://github.com/", params: "TARGET" },
            { name: "LinkedIn Search", url: "https://www.linkedin.com/search/results/all/?keywords=", params: "TARGET" },
        ],
        "Google Dorking: Discovery": [
            { name: "Subdomains", url: "https://google.com/search?q=site:*.TARGET", params: "" },
            { name: "Directory Listing", url: "https://www.google.com/search?q=site:TARGET intitle:index.of", params: "" },
            { name: "S3 Buckets", url: "https://www.google.com/search?q=site:s3.amazonaws.com TARGET", params: "" },
            { name: "Google Cloud Storage", url: "https://www.google.com/search?q=site:storage.googleapis.com TARGET", params: "" },
            { name: "Azure Blobs", url: "https://www.google.com/search?q=site:blob.core.windows.net TARGET", params: "" },
            { name: "Dev Tools", url: "https://www.google.com/search?q=site:TARGET inurl:(jenkins OR gitlab OR bitbucket OR jira OR confluence)", params: "" },
        ],
        "Google Dorking: Sensitive Files": [
            { name: "Log Files", url: "https://www.google.com/search?q=site:TARGET filetype:log", params: "" },
            { name: "Config Files", url: "https://www.google.com/search?q=site:TARGET filetype:conf OR filetype:config OR filetype:ini", params: "" },
            { name: "Documents", url: "https://www.google.com/search?q=site:TARGET ext:(doc OR docx OR odt OR pdf OR rtf OR pps OR csv)", params: "" },
            { name: "Databases", url: "https://www.google.com/search?q=site:TARGET filetype:sql OR filetype:db OR filetype:mdb", params: "" },
            { name: "Version Control", url: "https://www.google.com/search?q=site:TARGET inurl:(.git OR .svn OR .hg)", params: "" },
            { name: "WP Users", url: "https://www.google.com/search?q=site:TARGET filetype:sql intext:wp_users phpmyadmin", params: "" },
        ],
        "SEO & Website Analysis": [
            { name: "SimilarWeb", url: "http://www.similarweb.com/website/", params: "TARGET" },
            { name: "Moz Domain Analysis", url: "https://moz.com/domain-analysis?site=", params: "TARGET" },
            { name: "Ahrefs Backlink Checker", url: "https://ahrefs.com/backlink-checker?target=", params: "TARGET" },
            { name: "Host.io Backlinks", url: "https://host.io/backlinks/", params: "TARGET" },
            { name: "WMTips", url: "https://www.wmtips.com/tools/info/", params: "TARGET" },
        ],
        "Utilities & Screenshots": [
            { name: "Robots.txt", url: "https://TARGET/robots.txt", params: "" },
            { name: "Screenshot (URLScan)", url: "https://urlscan.io/domain/", params: "TARGET" },
            { name: "Screenshot (Informer)", url: "https://website.informer.com/", params: "TARGET#tab_stats" },
            { name: "Screenshot (DomainIQ)", url: "https://www.domainiq.com/snapshot_history#", params: "TARGET" },
            { name: "CopyScape Plagiarism", url: "https://www.copyscape.com/?q=http://", params: "TARGET" },
            { name: "Check Short URL", url: "http://checkshorturl.com/expand.php?u=", params: "TARGET" },
        ]
    };

    const toolsContainer = document.getElementById('tools-container');
    const targetInput = document.getElementById('targetInput');

    function generateTools() {
        toolsContainer.innerHTML = '';
        for (const category in osintTools) {
            const categoryHeader = document.createElement('div');
            categoryHeader.className = 'tool-category';
            categoryHeader.innerHTML = `<h2>${category}</h2>`;
            toolsContainer.appendChild(categoryHeader);

            const grid = document.createElement('div');
            grid.className = 'tool-grid';

            osintTools[category].forEach(tool => {
                const button = document.createElement('button');
                button.className = 'tool-button';
                button.textContent = tool.name;

                button.addEventListener('click', () => {
                    let targetValue = targetInput.value.trim();
                    if (targetValue === '') {
                        alert('Please enter a target.');
                        return;
                    }

                    // Replace the placeholder with the actual target
                    let finalUrl = (tool.url + tool.params).replace(/TARGET/g, encodeURIComponent(targetValue));
                    
                    window.open(finalUrl, '_blank');
                });
                grid.appendChild(button);
            });
            toolsContainer.appendChild(grid);
        }
    }

    generateTools();
});
