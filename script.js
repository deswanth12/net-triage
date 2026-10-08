/**
 * Network Traffic Triage Tool - Core Client-Side Logic
 * Pure Vanilla JavaScript • Zero External Dependencies • 100% Local Browser Analysis
 */

'use strict';

// ==========================================================================
// Embedded Safe Demo Scenarios (Enables 100% offline file:/// execution)
// ==========================================================================

const DEMO_SAMPLES = {
  normal: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","192.168.1.15","192.168.1.1","DNS","74","Standard query 0x0002 A internal.corp.local"
"2","0.001205","192.168.1.1","192.168.1.15","DNS","90","Standard query response 0x0002 A internal.corp.local A 192.168.1.50"
"3","0.002410","192.168.1.15","192.168.1.50","TCP","66","49152 -> 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"4","0.003100","192.168.1.50","192.168.1.15","TCP","66","443 -> 49152 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
"5","0.003550","192.168.1.15","192.168.1.50","TCP","54","49152 -> 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"6","0.005120","192.168.1.15","192.168.1.50","TLSv1.3","517","Client Hello"
"7","0.006880","192.168.1.50","192.168.1.15","TLSv1.3","1420","Server Hello, Change Cipher Spec, Application Data"
"8","0.007150","192.168.1.15","192.168.1.50","TCP","54","49152 -> 443 [ACK] Seq=464 Ack=1367 Win=64240 Len=0"
"9","0.010200","192.168.1.20","192.168.1.1","DNS","71","Standard query 0x12a4 A gateway.update.service"
"10","0.011800","192.168.1.1","192.168.1.20","DNS","87","Standard query response 0x12a4 A 198.51.100.25"
"11","0.012500","192.168.1.20","198.51.100.25","TCP","66","51234 -> 80 [SYN] Seq=0 Win=64240 Len=0"
"12","0.013100","198.51.100.25","192.168.1.20","TCP","66","80 -> 51234 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0"
"13","0.013400","192.168.1.20","198.51.100.25","TCP","54","51234 -> 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"14","0.014200","192.168.1.20","198.51.100.25","HTTP","145","GET /status HTTP/1.1"
"15","0.016000","198.51.100.25","192.168.1.20","HTTP","230","HTTP/1.1 200 OK (text/plain)"
"16","0.020100","192.168.1.10","192.168.1.255","UDP","128","Source port: 5353 Destination port: 5353 Multicast DNS"
"17","0.025000","192.168.1.1","192.168.1.255","ARP","42","Who has 192.168.1.15? Tell 192.168.1.1"
"18","0.025200","192.168.1.15","192.168.1.1","ARP","42","192.168.1.15 is at 00:11:22:33:44:55"
"19","0.030000","192.168.1.12","192.168.1.1","NTP","90","NTP Version 4, client, poll 6"
"20","0.030500","192.168.1.1","192.168.1.12","NTP","90","NTP Version 4, server, poll 6"
"21","0.035000","192.168.1.15","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0001, seq=1/256, ttl=64"
"22","0.035400","192.168.1.1","192.168.1.15","ICMP","74","Echo (ping) reply    id=0x0001, seq=1/256, ttl=64"
"23","0.040000","192.168.1.30","192.168.1.1","DNS","68","Standard query 0x33b1 A time.cloudflare.com"
"24","0.041200","192.168.1.1","192.168.1.30","DNS","84","Standard query response 0x33b1 A 162.159.200.1"
"25","0.045000","192.168.1.30","162.159.200.1","NTP","90","NTP Version 4, client, poll 4"
"26","0.048000","162.159.200.1","192.168.1.30","NTP","90","NTP Version 4, server, poll 4"
"27","0.052000","192.168.1.15","192.168.1.50","TCP","54","49152 -> 443 [FIN, ACK] Seq=464 Ack=1367 Win=64240 Len=0"
"28","0.052300","192.168.1.50","192.168.1.15","TCP","54","443 -> 49152 [ACK] Seq=1367 Ack=465 Win=65535 Len=0"
"29","0.052800","192.168.1.50","192.168.1.15","TCP","54","443 -> 49152 [FIN, ACK] Seq=1367 Ack=465 Win=65535 Len=0"
"30","0.053100","192.168.1.15","192.168.1.50","TCP","54","49152 -> 443 [ACK] Seq=465 Ack=1368 Win=64240 Len=0"`,

  highVolume: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","192.168.1.10","192.168.1.1","DNS","72","Standard query 0x01a1 A updates.lan"
"2","0.001100","192.168.1.1","192.168.1.10","DNS","88","Standard query response 0x01a1 A 192.168.1.200"
"3","0.002000","192.168.1.55","192.168.1.200","TCP","66","55432 -> 8080 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"4","0.002500","192.168.1.200","192.168.1.55","TCP","66","8080 -> 55432 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
"5","0.002800","192.168.1.55","192.168.1.200","TCP","54","55432 -> 8080 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"6","0.003100","192.168.1.55","192.168.1.200","HTTP","350","POST /upload/backup.tar.gz HTTP/1.1"` +
  Array.from({ length: 55 }, (_, i) =>
    `\n"${i + 7}","${(0.0034 + i * 0.0003).toFixed(6)}","192.168.1.55","192.168.1.200","TCP","1514","55432 -> 8080 [ACK] Seq=${1000 + i * 1460} Ack=1 [TCP segment of a reassembled PDU]"`
  ).join(''),

  mixedLab: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x1001 A dc01.corp.local"
"2","0.001000","192.168.1.1","192.168.1.10","DNS","90","Standard query response 0x1001 A dc01.corp.local A 192.168.1.5"
"3","0.002000","192.168.1.10","192.168.1.5","TCP","66","49200 -> 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"4","0.002500","192.168.1.5","192.168.1.10","TCP","66","445 -> 49200 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
"5","0.002800","192.168.1.10","192.168.1.5","TCP","54","49200 -> 445 [ACK] Seq=1 Ack=1 Win=64240 Len=0"` +
  // ICMP Ping sweep (33 packets across 33 distinct destinations)
  Array.from({ length: 33 }, (_, i) =>
    `\n"${i + 6}","${(0.005 + i * 0.0005).toFixed(6)}","192.168.1.99","192.168.1.${i + 2}","ICMP","74","Echo (ping) request  id=0x0010, seq=${i + 1}/256"`
  ).join('') +
  // Port scan (14 unique ports on 192.168.1.100)
  [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080].map((port, i) =>
    `\n"${i + 39}","${(0.025 + i * 0.0002).toFixed(6)}","192.168.1.99","192.168.1.100","TCP","66","441${10 + i} -> ${port} [SYN] Seq=0 Win=1024 Len=0"`
  ).join('') +
  // Repeated conversation (52 packets from 10.0.0.50 to 10.0.0.5)
  Array.from({ length: 52 }, (_, i) =>
    `\n"${i + 53}","${(0.030 + i * 0.0001).toFixed(6)}","10.0.0.50","10.0.0.5","TCP","1420","50000 -> 9000 [ACK] PDU block ${i + 1}"`
  ).join('')
};

// ==========================================================================
// Application State & Default Configurable Thresholds
// ==========================================================================

const DEFAULT_THRESHOLDS = {
  volume: 50,          // Rule 1: Packets per source
  destinations: 10,    // Rule 2: Unique destinations (host scan)
  ports: 10,           // Rule 3: Unique destination ports (port scan)
  icmp: 30,            // Rule 4: ICMP packets per source
  dns: 30,             // Rule 5: DNS queries per source
  repeated: 40,        // Rule 6: Source-to-Destination repeated packets
  syn: 15              // Rule 7: Repeated TCP SYN packets
};

let currentThresholds = { ...DEFAULT_THRESHOLDS };
let rawPackets = [];
let currentFileName = '';
let isDemoData = false;

// Active UI filters
let activeFilter = {
  search: '',
  protocol: 'ALL',
  severity: 'ALL'
};

// ==========================================================================
// DOM Element Cache
// ==========================================================================

const elements = {
  dropzone: document.getElementById('dropzone'),
  fileInput: document.getElementById('fileInput'),
  ingestStatus: document.getElementById('ingestStatus'),
  emptyState: document.getElementById('emptyState'),
  dashboardSection: document.getElementById('dashboardSection'),

  // Demo Buttons
  loadNormalBtn: document.getElementById('loadNormalBtn'),
  loadHighVolumeBtn: document.getElementById('loadHighVolumeBtn'),
  loadMixedLabBtn: document.getElementById('loadMixedLabBtn'),

  // Config Accordion & Form
  configToggle: document.getElementById('configToggle'),
  configPanel: document.getElementById('configPanel'),
  threshVolume: document.getElementById('threshVolume'),
  threshDestinations: document.getElementById('threshDestinations'),
  threshPorts: document.getElementById('threshPorts'),
  threshIcmp: document.getElementById('threshIcmp'),
  threshDns: document.getElementById('threshDns'),
  threshRepeated: document.getElementById('threshRepeated'),
  threshSyn: document.getElementById('threshSyn'),
  applyThresholdsBtn: document.getElementById('applyThresholdsBtn'),
  resetDefaultsBtn: document.getElementById('resetDefaultsBtn'),

  // Summary Metrics
  statTotalPackets: document.getElementById('statTotalPackets'),
  statAvgLength: document.getElementById('statAvgLength'),
  statUniqueSources: document.getElementById('statUniqueSources'),
  statTopSource: document.getElementById('statTopSource'),
  statUniqueDests: document.getElementById('statUniqueDests'),
  statTopDest: document.getElementById('statTopDest'),
  statTopProtocol: document.getElementById('statTopProtocol'),
  statProtocolCount: document.getElementById('statProtocolCount'),
  statInvestScore: document.getElementById('statInvestScore'),
  scoreLabel: document.getElementById('scoreLabel'),
  scoreBreakdownHint: document.getElementById('scoreBreakdownHint'),
  scoreDetailsBox: document.getElementById('scoreDetailsBox'),
  scoreFormulaText: document.getElementById('scoreFormulaText'),

  // Alerts
  alertsContainer: document.getElementById('alertsContainer'),
  alertCountBadge: document.getElementById('alertCountBadge'),
  severityFilter: document.getElementById('severityFilter'),

  // Visual Breakdown & Tables
  protocolBarsContainer: document.getElementById('protocolBarsContainer'),
  topSourcesBody: document.getElementById('topSourcesBody'),
  topDestsBody: document.getElementById('topDestsBody'),
  topConvsBody: document.getElementById('topConvsBody'),
  packetListBody: document.getElementById('packetListBody'),
  filteredPacketCount: document.getElementById('filteredPacketCount'),

  // Interactive Filters
  searchInput: document.getElementById('searchInput'),
  protocolFilter: document.getElementById('protocolFilter'),
  clearFiltersBtn: document.getElementById('clearFiltersBtn'),

  // Modal Guide
  toggleGuideBtn: document.getElementById('toggleGuideBtn'),
  analystGuideModal: document.getElementById('analystGuideModal'),
  closeGuideBtn: document.getElementById('closeGuideBtn'),
  closeGuideBottomBtn: document.getElementById('closeGuideBottomBtn')
};

// ==========================================================================
// Resilient RFC-4180 Client-Side CSV Parser
// ==========================================================================

/**
 * Parses raw CSV text handling quotes, embedded commas, and whitespace.
 * Prevents regex backtracking and memory exhaustion.
 */
function parseCsvRows(csvText) {
  const rows = [];
  let currentRow = [];
  let currentField = '';
  let insideQuotes = false;

  const length = csvText.length;
  for (let i = 0; i < length; i++) {
    const char = csvText[i];
    const nextChar = i + 1 < length ? csvText[i + 1] : '';

    if (char === '"') {
      if (insideQuotes && nextChar === '"') {
        currentField += '"';
        i++; // skip escaped quote
      } else {
        insideQuotes = !insideQuotes;
      }
    } else if (char === ',' && !insideQuotes) {
      currentRow.push(currentField);
      currentField = '';
    } else if ((char === '\r' || char === '\n') && !insideQuotes) {
      if (char === '\r' && nextChar === '\n') {
        i++; // consume CRLF
      }
      currentRow.push(currentField);
      if (currentRow.some(val => val.trim().length > 0)) {
        rows.push(currentRow);
      }
      currentRow = [];
      currentField = '';
    } else {
      currentField += char;
    }
  }

  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField);
    if (currentRow.some(val => val.trim().length > 0)) {
      rows.push(currentRow);
    }
  }

  return rows;
}

/**
 * Normalizes column header variations from Wireshark exports.
 */
function mapColumnIndices(headerRow) {
  const mapping = {
    source: -1,
    destination: -1,
    protocol: -1,
    length: -1,
    info: -1,
    time: -1,
    number: -1
  };

  headerRow.forEach((col, index) => {
    const clean = col.trim().toLowerCase().replace(/[^a-z0-9._]/g, '');

    // Source field variations
    if (['source', 'src', 'ip.src', 'sourceip', 'srcip', 'sourceaddress'].includes(clean)) {
      if (mapping.source === -1) mapping.source = index;
    }
    // Destination variations
    else if (['destination', 'dst', 'dest', 'ip.dst', 'destinationip', 'dstip', 'destinationaddress'].includes(clean)) {
      if (mapping.destination === -1) mapping.destination = index;
    }
    // Protocol variations
    else if (['protocol', 'proto', 'ip.proto'].includes(clean)) {
      if (mapping.protocol === -1) mapping.protocol = index;
    }
    // Length variations
    else if (['length', 'len', 'frame.len', 'framelength', 'bytes', 'packetlength'].includes(clean)) {
      if (mapping.length === -1) mapping.length = index;
    }
    // Info variations
    else if (['info', 'information', 'summary', 'packetinfo'].includes(clean)) {
      if (mapping.info === -1) mapping.info = index;
    }
    // Time variations
    else if (['time', 'timestamp', 'frame.time', 'time_relative'].includes(clean)) {
      if (mapping.time === -1) mapping.time = index;
    }
    // Packet number
    else if (['no.', 'no', 'number', 'frame.number'].includes(clean)) {
      if (mapping.number === -1) mapping.number = index;
    }
  });

  return mapping;
}

/**
 * Parses and validates raw CSV content into sanitized packet objects.
 */
function ingestCsvContent(csvString, fileName, isDemo = false) {
  currentFileName = fileName;
  isDemoData = isDemo;

  if (!csvString || !csvString.trim()) {
    showIngestStatus('error', 'The provided file is empty. Please select a valid Wireshark CSV file.');
    return;
  }

  const rows = parseCsvRows(csvString);
  if (rows.length < 2) {
    showIngestStatus('error', 'The CSV file does not contain enough data (headers or packet rows missing).');
    return;
  }

  const headers = rows[0];
  const colMap = mapColumnIndices(headers);

  // Check required fields
  const missingRequired = [];
  if (colMap.source === -1) missingRequired.push('Source (e.g. Source, src, ip.src)');
  if (colMap.destination === -1) missingRequired.push('Destination (e.g. Destination, dst, ip.dst)');

  if (missingRequired.length > 0) {
    const errText = `Unable to parse: missing required column(s): ${missingRequired.join(', ')}. In Wireshark, ensure these columns are visible in the packet list before exporting.`;
    showIngestStatus('error', errText);
    return;
  }

  // Check optional fields
  const missingOptional = [];
  if (colMap.protocol === -1) missingOptional.push('Protocol');
  if (colMap.length === -1) missingOptional.push('Length');
  if (colMap.info === -1) missingOptional.push('Info (port scan & SYN analysis rules disabled)');

  // Build sanitized packets
  const packets = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const source = (row[colMap.source] || '').trim();
    const destination = (row[colMap.destination] || '').trim();

    if (!source && !destination) continue; // Skip completely blank lines

    const packet = {
      no: colMap.number !== -1 && row[colMap.number] ? row[colMap.number].trim() : String(i),
      time: colMap.time !== -1 && row[colMap.time] ? row[colMap.time].trim() : '',
      source: source || 'Unknown Source',
      destination: destination || 'Unknown Destination',
      protocol: colMap.protocol !== -1 && row[colMap.protocol] ? row[colMap.protocol].trim().toUpperCase() : 'UNKNOWN',
      length: colMap.length !== -1 && row[colMap.length] ? parseInt(row[colMap.length], 10) || 0 : 0,
      info: colMap.info !== -1 && row[colMap.info] ? row[colMap.info].trim() : ''
    };

    packets.push(packet);
  }

  if (packets.length === 0) {
    showIngestStatus('error', 'No valid packet records found in the CSV.');
    return;
  }

  rawPackets = packets;

  let statusMsg = `Successfully parsed <strong>${packets.length}</strong> packets from <em>${escapeHtml(fileName)}</em>.`;
  let statusType = 'success';

  if (missingOptional.length > 0) {
    statusType = 'warning';
    statusMsg += ` <span style="font-size:0.8em; margin-left:8px;">(Notice: Missing optional column(s): ${missingOptional.join(', ')})</span>`;
  }

  showIngestStatus(statusType, statusMsg, isDemo);
  elements.emptyState.classList.add('hidden');
  elements.dashboardSection.classList.remove('hidden');

  populateProtocolFilterDropdown();
  runAnalysisAndRender();
}

/**
 * Display ingestion status and error notifications safely.
 */
function showIngestStatus(type, htmlMessage, isDemo = false) {
  elements.ingestStatus.className = `ingest-status ${type}`;
  elements.ingestStatus.classList.remove('hidden');

  let badge = isDemo ? '<span class="demo-active-badge">DEMO DATA</span>' : '';
  elements.ingestStatus.innerHTML = `<div>${badge} ${htmlMessage}</div>`;
}

// ==========================================================================
// Triage & Detection Rule Engine (Explainable, Rule-Based, Zero ML)
// ==========================================================================

/**
 * Helper to extract destination port from Wireshark Info column.
 * Matches patterns like "44101 -> 80 [SYN]", "Destination port: 53", "55432 > 8080"
 */
function extractDestinationPort(infoStr) {
  if (!infoStr) return null;

  // Arrow notation: "49152 -> 443" or "55432 > 8080"
  const arrowMatch = infoStr.match(/(?:->|>)\s*(\d+)/);
  if (arrowMatch) {
    const port = parseInt(arrowMatch[1], 10);
    if (port > 0 && port <= 65535) return port;
  }

  // Explicit keyword: "Destination port: 53" or "Dst Port: 53"
  const explicitMatch = infoStr.match(/(?:destination\s*port|dst\s*port|dport)[:\s]+(\d+)/i);
  if (explicitMatch) {
    const port = parseInt(explicitMatch[1], 10);
    if (port > 0 && port <= 65535) return port;
  }

  return null;
}

/**
 * Runs the rule-based triage detection engine.
 * Generates transparent alerts and an explainable investigation score.
 */
function evaluateDetectionRules(packets, thresholds) {
  const alerts = [];
  let investigationScore = 0;
  const scoreBreakdown = [];

  // Aggregation maps
  const sourcePacketCounts = new Map();
  const sourceDestMap = new Map();              // source -> Set(destinations)
  const sourceDestPortsMap = new Map();         // `${source}->${dest}` -> Set(destPorts)
  const sourceIcmpCounts = new Map();
  const sourceDnsCounts = new Map();
  const conversationCounts = new Map();         // `${source}->${destination}` -> { count, protocols: Map() }
  const sourceSynCounts = new Map();

  for (const pkt of packets) {
    const src = pkt.source;
    const dst = pkt.destination;
    const proto = pkt.protocol;
    const info = pkt.info;

    // Packets per source
    sourcePacketCounts.set(src, (sourcePacketCounts.get(src) || 0) + 1);

    // Unique destinations per source
    if (!sourceDestMap.has(src)) sourceDestMap.set(src, new Set());
    sourceDestMap.get(src).add(dst);

    // Port scanning data
    const destPort = extractDestinationPort(info);
    if (destPort) {
      const srcDestKey = `${src}->${dst}`;
      if (!sourceDestPortsMap.has(srcDestKey)) sourceDestPortsMap.set(srcDestKey, new Set());
      sourceDestPortsMap.get(srcDestKey).add(destPort);
    }

    // ICMP packets
    if (proto === 'ICMP' || proto.includes('ICMP')) {
      sourceIcmpCounts.set(src, (sourceIcmpCounts.get(src) || 0) + 1);
    }

    // DNS packets
    if (proto === 'DNS' || proto.includes('DNS') || info.toLowerCase().includes('standard query')) {
      sourceDnsCounts.set(src, (sourceDnsCounts.get(src) || 0) + 1);
    }

    // Source-to-Destination conversations
    const convKey = `${src} -> ${dst}`;
    if (!conversationCounts.has(convKey)) {
      conversationCounts.set(convKey, { count: 0, protocols: new Map() });
    }
    const conv = conversationCounts.get(convKey);
    conv.count++;
    conv.protocols.set(proto, (conv.protocols.get(proto) || 0) + 1);

    // TCP SYN analysis
    if (proto === 'TCP' && info.includes('[SYN]') && !info.includes('[SYN, ACK]')) {
      sourceSynCounts.set(src, (sourceSynCounts.get(src) || 0) + 1);
    }
  }

  // ------------------------------------------------------------------------
  // RULE 1 — HIGH PACKET VOLUME
  // ------------------------------------------------------------------------
  sourcePacketCounts.forEach((count, source) => {
    if (count > thresholds.volume) {
      const sev = count > thresholds.volume * 2.5 ? 'MEDIUM' : 'LOW';
      const points = sev === 'MEDIUM' ? 25 : 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High Volume (${source})`);

      alerts.push({
        id: `rule1-${source}`,
        name: 'High Packet Volume',
        severity: sev,
        source: source,
        destination: 'Various',
        activity: `${count} packets generated by host`,
        threshold: `Threshold: > ${thresholds.volume} packets`,
        whyMatters: 'A host generating significantly more traffic than expected may warrant investigation to determine if anomalous bulk transfer or automated processes are occurring.',
        benignExplanations: [
          'Legitimate file transfers or local network backups',
          'Operating system or application software updates',
          'Streaming video, VoIP, or video conferencing',
          'Automated data ingestion or database replication jobs'
        ],
        suggestedInvestigation: [
          'Identify device owner, hostname, and primary operational purpose.',
          'Review the destination addresses to verify whether they are expected services.',
          'Check whether the burst correlates with an authorized scheduled task.',
          'Review endpoint process logs (EDR/Task Manager) on the source host.'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 2 — POSSIBLE HOST SCANNING
  // ------------------------------------------------------------------------
  sourceDestMap.forEach((destSet, source) => {
    const uniqueDests = destSet.size;
    if (uniqueDests > thresholds.destinations) {
      const points = 25;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Possible Host Scan (${source})`);

      alerts.push({
        id: `rule2-${source}`,
        name: 'Possible Network Host Scanning',
        severity: 'MEDIUM',
        source: source,
        destination: `Multiple (${uniqueDests} unique targets)`,
        activity: `Transmitted traffic to ${uniqueDests} unique destination hosts`,
        threshold: `Threshold: > ${thresholds.destinations} destinations`,
        whyMatters: 'A single host communicating with an unusually large number of destination systems over a brief capture window may indicate network reconnaissance or host discovery.',
        benignExplanations: [
          'Enterprise asset discovery, IT inventory, or vulnerability scanning systems',
          'Network management tools or SNMP/NetBIOS polling scripts',
          'Multi-cast discovery protocols (mDNS, SSDP, LLMNR)',
          'Peer-to-peer applications or distributed file sync utilities'
        ],
        suggestedInvestigation: [
          'Check if the source IP is assigned to an authorized administrative scanner.',
          'Inspect the protocol breakdown: are these ping sweeps (ICMP) or connection probes?',
          'Verify whether the targeted IP addresses belong to valid subnets or are sequential.',
          'Interview the device owner to confirm whether discovery software was intentionally executed.'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 3 — POSSIBLE PORT SCANNING
  // ------------------------------------------------------------------------
  sourceDestPortsMap.forEach((portsSet, key) => {
    const portCount = portsSet.size;
    if (portCount > thresholds.ports) {
      const [src, dst] = key.split('->');
      const points = 25;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Possible Port Scan (${src} -> ${dst})`);

      alerts.push({
        id: `rule3-${key}`,
        name: 'Possible Port Scanning',
        severity: 'MEDIUM',
        source: src,
        destination: dst,
        activity: `Contacted ${portCount} unique destination ports on single target`,
        threshold: `Threshold: > ${thresholds.ports} unique ports`,
        whyMatters: 'Systematically probing numerous ports on a single host is a classic hallmark of service discovery or reconnaissance aimed at finding exposed services.',
        benignExplanations: [
          'Authorized security assessment tools (e.g., Nmap, Nessus, OpenVAS)',
          'Complex enterprise applications that establish multi-channel connections',
          'Network service monitoring or load balancer health-check probes',
          'Application developer testing a range of local debug ports'
        ],
        suggestedInvestigation: [
          'Examine the targeted ports: are they common administrative services (21, 22, 80, 443, 3389)?',
          'Determine if the connection attempts received replies (SYN-ACK) or resets (RST).',
          'Verify if the scanning host holds an authorized change-management ticket.',
          'Review the target host firewall and security event logs.'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 4 — HIGH ICMP ACTIVITY
  // ------------------------------------------------------------------------
  sourceIcmpCounts.forEach((count, source) => {
    if (count > thresholds.icmp) {
      const points = 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High ICMP (${source})`);

      alerts.push({
        id: `rule4-${source}`,
        name: 'High ICMP Activity',
        severity: 'LOW',
        source: source,
        destination: 'Various targets',
        activity: `Sent ${count} ICMP control packets`,
        threshold: `Threshold: > ${thresholds.icmp} ICMP packets`,
        whyMatters: 'Unusually high volume of ICMP packets may indicate network ping sweeps, path MTU discovery probes, or automated reachability monitoring.',
        benignExplanations: [
          'System administrator actively troubleshooting network latency or packet loss',
          'Continuous ping (ping -t) left running by an engineer',
          'Network monitoring servers (Nagios, Zabbix, PRTG) measuring uptime',
          'VPN tunnels conducting keepalive probes'
        ],
        suggestedInvestigation: [
          'Check ICMP types: are they Echo Requests (Type 8), Replies (Type 0), or Destination Unreachable (Type 3)?',
          'Confirm if continuous diagnostic pings were initiated by IT personnel.',
          'Inspect whether the ICMP probes targeted sequential addresses (ping sweep).'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 5 — HIGH DNS QUERY ACTIVITY
  // ------------------------------------------------------------------------
  sourceDnsCounts.forEach((count, source) => {
    if (count > thresholds.dns) {
      const points = 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High DNS Activity (${source})`);

      alerts.push({
        id: `rule5-${source}`,
        name: 'High DNS Query Volume',
        severity: 'LOW',
        source: source,
        destination: 'DNS Resolvers',
        activity: `Generated ${count} DNS query packets`,
        threshold: `Threshold: > ${thresholds.dns} DNS packets`,
        whyMatters: 'Spikes in DNS query volume may signify aggressive domain lookups, automated crawlers, misconfigured caching, or potential DNS tunneling/beaconing.',
        benignExplanations: [
          'Web browser loading complex modern websites with dozens of third-party domains',
          'Internal mail server conducting spam checks (DNSBL lookups)',
          'Software updater attempting resolution across redundant mirror CDNs',
          'Local DNS caching service failure forcing repeated queries'
        ],
        suggestedInvestigation: [
          'Inspect the requested domain names in the Info column for unusually long or random subdomains.',
          'Check whether queries are directed to authorized enterprise DNS resolvers.',
          'Verify if the endpoint runs a high-volume application or web crawler.'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 6 — REPEATED SOURCE-TO-DESTINATION COMMUNICATION
  // ------------------------------------------------------------------------
  conversationCounts.forEach((data, convKey) => {
    if (data.count > thresholds.repeated) {
      const [src, dst] = convKey.split(' -> ');
      // Get primary protocol
      let topProto = 'TCP';
      let maxPCount = 0;
      data.protocols.forEach((pCount, pName) => {
        if (pCount > maxPCount) {
          maxPCount = pCount;
          topProto = pName;
        }
      });

      const points = 10;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Sustained Pair Flow (${src} -> ${dst})`);

      alerts.push({
        id: `rule6-${convKey}`,
        name: 'Repeated Host-to-Host Communication',
        severity: 'INFORMATIONAL',
        source: src,
        destination: dst,
        activity: `${data.count} packets exchanged (${topProto})`,
        threshold: `Threshold: > ${thresholds.repeated} conversation packets`,
        whyMatters: 'Heavy one-to-one communication patterns indicate an active data channel. Analysts check these to verify whether large transfers or automated beaconing are legitimate.',
        benignExplanations: [
          'Active remote desktop session (RDP, SSH, VNC)',
          'Streaming media, web browsing session, or cloud synchronization',
          'Database client executing large batch queries',
          'Internal file copy via SMB or SFTP'
        ],
        suggestedInvestigation: [
          'Identify what application protocol is dominating the session.',
          'Check whether the destination IP belongs to an approved internal server or external CDN.',
          'Correlate the transferred data volume with expected user activity.'
        ]
      });
    }
  });

  // ------------------------------------------------------------------------
  // RULE 7 — TCP SYN HEAVY ACTIVITY
  // ------------------------------------------------------------------------
  sourceSynCounts.forEach((count, source) => {
    if (count > thresholds.syn) {
      const points = 20;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Heavy TCP SYN (${source})`);

      alerts.push({
        id: `rule7-${source}`,
        name: 'TCP SYN Heavy Activity',
        severity: 'MEDIUM',
        source: source,
        destination: 'Various targets',
        activity: `Transmitted ${count} TCP SYN connection initiation packets`,
        threshold: `Threshold: > ${thresholds.syn} SYN packets`,
        whyMatters: 'A cluster of TCP SYN packets indicates repeated attempts to establish new connections. When frequent, it can correlate with port scanning or connection failure cascades.',
        benignExplanations: [
          'Client application rapidly connecting to multiple web assets or APIs',
          'Target service is down or unresponsive, causing client retry loops',
          'Network benchmark or throughput load testing tool',
          'P2P file distribution client seeking active seeders'
        ],
        suggestedInvestigation: [
          'Determine if the target hosts are replying with SYN-ACK or if packets are going unanswered.',
          'Review whether this host is trying to connect to a specific failing server.',
          'Check if the host is executing an automated security scan.'
        ]
      });
    }
  });

  return {
    alerts,
    score: Math.min(investigationScore, 100),
    breakdown: scoreBreakdown
  };
}

// ==========================================================================
// Dashboard Analysis, Aggregation & Rendering
// ==========================================================================

function runAnalysisAndRender() {
  if (rawPackets.length === 0) return;

  // 1. Detection Rules Evaluation
  const ruleResults = evaluateDetectionRules(rawPackets, currentThresholds);

  // 2. Metrics Aggregations
  let totalBytes = 0;
  const sourcesMap = new Map();
  const destsMap = new Map();
  const protocolsMap = new Map();
  const conversationsMap = new Map();

  for (const pkt of rawPackets) {
    totalBytes += pkt.length;

    // Sources
    sourcesMap.set(pkt.source, (sourcesMap.get(pkt.source) || 0) + 1);

    // Destinations
    destsMap.set(pkt.destination, (destsMap.get(pkt.destination) || 0) + 1);

    // Protocols
    protocolsMap.set(pkt.protocol, (protocolsMap.get(pkt.protocol) || 0) + 1);

    // Conversations
    const convKey = `${pkt.source} -> ${pkt.destination}`;
    if (!conversationsMap.has(convKey)) {
      conversationsMap.set(convKey, {
        source: pkt.source,
        destination: pkt.destination,
        count: 0,
        protocols: new Map()
      });
    }
    const conv = conversationsMap.get(convKey);
    conv.count++;
    conv.protocols.set(pkt.protocol, (conv.protocols.get(pkt.protocol) || 0) + 1);
  }

  // Find Top Source
  let topSource = 'None';
  let maxSourceCount = 0;
  sourcesMap.forEach((count, src) => {
    if (count > maxSourceCount) {
      maxSourceCount = count;
      topSource = src;
    }
  });

  // Find Top Dest
  let topDest = 'None';
  let maxDestCount = 0;
  destsMap.forEach((count, dst) => {
    if (count > maxDestCount) {
      maxDestCount = count;
      topDest = dst;
    }
  });

  // Find Top Protocol
  let topProtocol = 'None';
  let maxProtoCount = 0;
  protocolsMap.forEach((count, proto) => {
    if (count > maxProtoCount) {
      maxProtoCount = count;
      topProtocol = proto;
    }
  });

  const avgLength = rawPackets.length > 0 ? Math.round(totalBytes / rawPackets.length) : 0;

  // Render Metric Cards
  elements.statTotalPackets.textContent = rawPackets.length.toLocaleString();
  elements.statAvgLength.textContent = `Avg Length: ${avgLength} Bytes`;

  elements.statUniqueSources.textContent = sourcesMap.size.toLocaleString();
  elements.statTopSource.textContent = `Top: ${topSource} (${maxSourceCount} pkts)`;

  elements.statUniqueDests.textContent = destsMap.size.toLocaleString();
  elements.statTopDest.textContent = `Top: ${topDest} (${maxDestCount} pkts)`;

  elements.statTopProtocol.textContent = topProtocol;
  elements.statProtocolCount.textContent = `${maxProtoCount.toLocaleString()} packets (${Math.round((maxProtoCount / rawPackets.length) * 100)}%)`;

  // Render Investigation Score
  renderInvestigationScore(ruleResults.score, ruleResults.breakdown);

  // Render Alerts
  renderAlerts(ruleResults.alerts);

  // Render Visual Protocol Bars
  renderProtocolBars(protocolsMap, rawPackets.length);

  // Render Top Sources Table
  renderTopSources(sourcesMap, rawPackets.length);

  // Render Top Destinations Table
  renderTopDestinations(destsMap, rawPackets.length);

  // Render Top Conversations Table
  renderTopConversations(conversationsMap);

  // Render Packet Preview Table (with active filters)
  renderFilteredPacketPreview();
}

/**
 * Render Investigation Score and transparent penalty breakdown.
 */
function renderInvestigationScore(score, breakdown) {
  elements.statInvestScore.textContent = score;

  let labelClass = 'score-baseline';
  let labelText = 'Baseline Traffic';

  if (score >= 60) {
    labelClass = 'score-high';
    labelText = 'Notable Priority';
  } else if (score >= 30) {
    labelClass = 'score-elevated';
    labelText = 'Elevated Activity';
  }

  elements.scoreLabel.className = `score-pill ${labelClass}`;
  elements.scoreLabel.textContent = labelText;

  elements.scoreBreakdownHint.textContent = `${breakdown.length} rule contribution${breakdown.length === 1 ? '' : 's'}`;

  if (breakdown.length > 0) {
    elements.scoreDetailsBox.classList.remove('hidden');
    elements.scoreFormulaText.textContent = breakdown.join(' • ');
  } else {
    elements.scoreDetailsBox.classList.remove('hidden');
    elements.scoreFormulaText.textContent = 'No active investigation triggers (all within configured baseline thresholds)';
  }
}

/**
 * Render Triage Alert Cards with full analyst context.
 */
function renderAlerts(alerts) {
  const container = elements.alertsContainer;
  container.innerHTML = '';

  const filtered = activeFilter.severity === 'ALL'
    ? alerts
    : alerts.filter(a => a.severity.toUpperCase() === activeFilter.severity);

  elements.alertCountBadge.textContent = `${filtered.length} Finding${filtered.length === 1 ? '' : 's'}`;

  if (filtered.length === 0) {
    const emptyCard = document.createElement('div');
    emptyCard.className = 'no-alerts-card';
    emptyCard.innerHTML = `
      <h4>No Anomalous Alerts Triggered</h4>
      <p>Network traffic patterns are currently within all configured detection thresholds.
      Remember: absence of alerts indicates baseline traffic under these rules, not necessarily an absence of all risk.</p>
    `;
    container.appendChild(emptyCard);
    return;
  }

  filtered.forEach(alert => {
    const card = document.createElement('article');
    card.className = `alert-card sev-${alert.severity.toLowerCase()}`;

    const benignListHtml = alert.benignExplanations.map(item => `<li>${escapeHtml(item)}</li>`).join('');
    const stepsListHtml = alert.suggestedInvestigation.map(step => `<li>${escapeHtml(step)}</li>`).join('');

    card.innerHTML = `
      <div class="alert-top">
        <div class="alert-title-row">
          <span class="badge-sev sev-${alert.severity.toLowerCase()}">${alert.severity}</span>
          <h3 class="alert-name">${escapeHtml(alert.name)}</h3>
        </div>
        <div class="alert-hosts-meta">
          Source: <span>${escapeHtml(alert.source)}</span> | Destination: <span>${escapeHtml(alert.destination)}</span>
        </div>
      </div>

      <div class="alert-evidence-grid">
        <div class="evidence-item">
          <strong>Observed Activity</strong>
          <span>${escapeHtml(alert.activity)}</span>
        </div>
        <div class="evidence-item">
          <strong>Configured Rule Parameter</strong>
          <span>${escapeHtml(alert.threshold)}</span>
        </div>
      </div>

      <div class="alert-sections-grid">
        <div class="alert-block">
          <h4>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
            Why This Matters
          </h4>
          <p>${escapeHtml(alert.whyMatters)}</p>
        </div>

        <div class="alert-block">
          <h4>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            Possible Benign Explanations
          </h4>
          <ul>${benignListHtml}</ul>
        </div>
      </div>

      <div class="alert-investigation-box">
        <h4>Suggested SOC Investigation Workflow</h4>
        <ol>${stepsListHtml}</ol>
      </div>
    `;

    container.appendChild(card);
  });
}

/**
 * Render visual CSS bars for Protocol Distribution.
 */
function renderProtocolBars(protocolsMap, totalPackets) {
  const container = elements.protocolBarsContainer;
  container.innerHTML = '';

  const sorted = Array.from(protocolsMap.entries()).sort((a, b) => b[1] - a[1]);

  sorted.forEach(([proto, count]) => {
    const pct = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;

    const row = document.createElement('div');
    row.className = 'proto-bar-row';

    // Normalize proto name for css accent styling
    const cleanProto = proto.toUpperCase().replace(/[^A-Z]/g, '');

    row.innerHTML = `
      <div class="proto-bar-labels">
        <span class="proto-bar-name">${escapeHtml(proto)}</span>
        <span class="proto-bar-stats">${count.toLocaleString()} pkts (${pct}%)</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill proto-${cleanProto}" style="width: ${pct}%"></div>
      </div>
    `;

    container.appendChild(row);
  });
}

/**
 * Render Top 10 Source Hosts table.
 */
function renderTopSources(sourcesMap, totalPackets) {
  const tbody = elements.topSourcesBody;
  tbody.innerHTML = '';

  const sorted = Array.from(sourcesMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  sorted.forEach(([src, count], index) => {
    const pct = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cell-rank">#${index + 1}</td>
      <td class="cell-mono">${escapeHtml(src)}</td>
      <td>${count.toLocaleString()}</td>
      <td>${pct}%</td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Render Top 10 Destination Hosts table.
 */
function renderTopDestinations(destsMap, totalPackets) {
  const tbody = elements.topDestsBody;
  tbody.innerHTML = '';

  const sorted = Array.from(destsMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  sorted.forEach(([dst, count], index) => {
    const pct = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cell-rank">#${index + 1}</td>
      <td class="cell-mono">${escapeHtml(dst)}</td>
      <td>${count.toLocaleString()}</td>
      <td>${pct}%</td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Render Top Host Conversations table.
 */
function renderTopConversations(conversationsMap) {
  const tbody = elements.topConvsBody;
  tbody.innerHTML = '';

  const sorted = Array.from(conversationsMap.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  sorted.forEach(conv => {
    let topProto = 'TCP';
    let maxCount = 0;
    conv.protocols.forEach((c, p) => {
      if (c > maxCount) {
        maxCount = c;
        topProto = p;
      }
    });

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cell-mono">${escapeHtml(conv.source)}</td>
      <td class="cell-mono">${escapeHtml(conv.destination)}</td>
      <td>${conv.count.toLocaleString()}</td>
      <td><span class="badge badge-subtle">${escapeHtml(topProto)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Dynamically populate protocol filter dropdown with active protocols.
 */
function populateProtocolFilterDropdown() {
  const select = elements.protocolFilter;
  select.innerHTML = '<option value="ALL">All Protocols</option>';

  const protos = new Set(rawPackets.map(p => p.protocol));
  Array.from(protos).sort().forEach(proto => {
    if (proto) {
      const opt = document.createElement('option');
      opt.value = proto;
      opt.textContent = proto;
      select.appendChild(opt);
    }
  });
}

/**
 * Render Filtered Raw Packet Log Preview table.
 */
function renderFilteredPacketPreview() {
  const tbody = elements.packetListBody;
  tbody.innerHTML = '';

  const query = activeFilter.search.toLowerCase();
  const proto = activeFilter.protocol;

  const matches = rawPackets.filter(pkt => {
    if (proto !== 'ALL' && pkt.protocol !== proto) return false;

    if (query) {
      const combined = `${pkt.source} ${pkt.destination} ${pkt.protocol} ${pkt.info}`.toLowerCase();
      if (!combined.includes(query)) return false;
    }

    return true;
  });

  elements.filteredPacketCount.textContent = `Showing ${Math.min(matches.length, 100)} of ${matches.length} matching`;

  const previewSlice = matches.slice(0, 100);

  if (previewSlice.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="7" style="text-align:center; padding:1.5rem; color:var(--text-dim);">No packets match current filter criteria.</td>';
    tbody.appendChild(tr);
    return;
  }

  previewSlice.forEach(pkt => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cell-rank">${escapeHtml(pkt.no)}</td>
      <td class="cell-mono" style="font-size:0.75rem;">${escapeHtml(pkt.time)}</td>
      <td class="cell-mono">${escapeHtml(pkt.source)}</td>
      <td class="cell-mono">${escapeHtml(pkt.destination)}</td>
      <td><span class="badge badge-subtle">${escapeHtml(pkt.protocol)}</span></td>
      <td>${pkt.length}</td>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(pkt.info)}">
        ${escapeHtml(pkt.info)}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// ==========================================================================
// Event Listeners & User Interactions
// ==========================================================================

function setupEventListeners() {
  // 1. File Upload Drag & Drop
  const dropzone = elements.dropzone;
  const fileInput = elements.fileInput;

  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  ['dragenter', 'dragover'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFileSelection(files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileSelection(fileInput.files[0]);
    }
  });

  // 2. Demo Buttons
  elements.loadNormalBtn.addEventListener('click', () => {
    ingestCsvContent(DEMO_SAMPLES.normal, 'normal-traffic.csv', true);
  });

  elements.loadHighVolumeBtn.addEventListener('click', () => {
    ingestCsvContent(DEMO_SAMPLES.highVolume, 'high-volume-traffic.csv', true);
  });

  elements.loadMixedLabBtn.addEventListener('click', () => {
    ingestCsvContent(DEMO_SAMPLES.mixedLab, 'mixed-soc-lab.csv', true);
  });

  // 3. Threshold Configuration Accordion
  elements.configToggle.addEventListener('click', () => {
    const isExpanded = elements.configToggle.getAttribute('aria-expanded') === 'true';
    elements.configToggle.setAttribute('aria-expanded', !isExpanded);
    elements.configPanel.classList.toggle('collapsed', isExpanded);
  });

  elements.configToggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      elements.configToggle.click();
    }
  });

  // Apply Thresholds
  elements.applyThresholdsBtn.addEventListener('click', () => {
    currentThresholds.volume = parseInt(elements.threshVolume.value, 10) || DEFAULT_THRESHOLDS.volume;
    currentThresholds.destinations = parseInt(elements.threshDestinations.value, 10) || DEFAULT_THRESHOLDS.destinations;
    currentThresholds.ports = parseInt(elements.threshPorts.value, 10) || DEFAULT_THRESHOLDS.ports;
    currentThresholds.icmp = parseInt(elements.threshIcmp.value, 10) || DEFAULT_THRESHOLDS.icmp;
    currentThresholds.dns = parseInt(elements.threshDns.value, 10) || DEFAULT_THRESHOLDS.dns;
    currentThresholds.repeated = parseInt(elements.threshRepeated.value, 10) || DEFAULT_THRESHOLDS.repeated;
    currentThresholds.syn = parseInt(elements.threshSyn.value, 10) || DEFAULT_THRESHOLDS.syn;

    runAnalysisAndRender();
  });

  // Reset Defaults
  elements.resetDefaultsBtn.addEventListener('click', () => {
    currentThresholds = { ...DEFAULT_THRESHOLDS };
    elements.threshVolume.value = DEFAULT_THRESHOLDS.volume;
    elements.threshDestinations.value = DEFAULT_THRESHOLDS.destinations;
    elements.threshPorts.value = DEFAULT_THRESHOLDS.ports;
    elements.threshIcmp.value = DEFAULT_THRESHOLDS.icmp;
    elements.threshDns.value = DEFAULT_THRESHOLDS.dns;
    elements.threshRepeated.value = DEFAULT_THRESHOLDS.repeated;
    elements.threshSyn.value = DEFAULT_THRESHOLDS.syn;

    runAnalysisAndRender();
  });

  // 4. Severity Alert Filter
  elements.severityFilter.addEventListener('change', (e) => {
    activeFilter.severity = e.target.value;
    const ruleResults = evaluateDetectionRules(rawPackets, currentThresholds);
    renderAlerts(ruleResults.alerts);
  });

  // 5. Interactive Table & Search Filters
  elements.searchInput.addEventListener('input', (e) => {
    activeFilter.search = e.target.value.trim();
    renderFilteredPacketPreview();
  });

  elements.protocolFilter.addEventListener('change', (e) => {
    activeFilter.protocol = e.target.value;
    renderFilteredPacketPreview();
  });

  elements.clearFiltersBtn.addEventListener('click', () => {
    activeFilter.search = '';
    activeFilter.protocol = 'ALL';
    elements.searchInput.value = '';
    elements.protocolFilter.value = 'ALL';
    renderFilteredPacketPreview();
  });

  // 6. Educational Analyst Guide Modal
  const openGuide = () => {
    elements.analystGuideModal.classList.remove('hidden');
    elements.toggleGuideBtn.setAttribute('aria-expanded', 'true');
  };

  const closeGuide = () => {
    elements.analystGuideModal.classList.add('hidden');
    elements.toggleGuideBtn.setAttribute('aria-expanded', 'false');
  };

  elements.toggleGuideBtn.addEventListener('click', openGuide);
  elements.closeGuideBtn.addEventListener('click', closeGuide);
  elements.closeGuideBottomBtn.addEventListener('click', closeGuide);

  elements.analystGuideModal.addEventListener('click', (e) => {
    if (e.target === elements.analystGuideModal) closeGuide();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !elements.analystGuideModal.classList.contains('hidden')) {
      closeGuide();
    }
  });
}

/**
 * Handle user file selection safely via FileReader API.
 */
function handleFileSelection(file) {
  if (!file) return;

  const validExtensions = ['.csv', '.txt'];
  const fileName = file.name || 'uploaded.csv';
  const hasValidExt = validExtensions.some(ext => fileName.toLowerCase().endsWith(ext));

  if (!hasValidExt) {
    showIngestStatus('error', `Invalid file extension for "${escapeHtml(fileName)}". Please upload a Wireshark CSV file.`);
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    ingestCsvContent(content, fileName, false);
  };
  reader.onerror = () => {
    showIngestStatus('error', `Error reading "${escapeHtml(fileName)}". Please verify file permissions.`);
  };

  reader.readAsText(file);
}

/**
 * Helper to prevent DOM-based XSS injection.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ==========================================================================
// Application Bootstrap
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
});
