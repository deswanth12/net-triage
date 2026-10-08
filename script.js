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
let latestRuleResults = { alerts: [], score: 0, breakdown: [] };

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

  // Workbench Actions
  exportReportBtn: document.getElementById('exportReportBtn'),
  activeCaptureLabel: document.getElementById('activeCaptureLabel'),

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

  // Traffic Timeline
  timelineCard: document.getElementById('timelineCard'),
  timelineContainer: document.getElementById('timelineContainer'),
  timelineFallback: document.getElementById('timelineFallback'),
  timelineSpanBadge: document.getElementById('timelineSpanBadge'),

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

  // Host Dossier Modal
  hostDossierModal: document.getElementById('hostDossierModal'),
  dossierIpTitle: document.getElementById('dossierIpTitle'),
  dossierCategoryBadge: document.getElementById('dossierCategoryBadge'),
  dossierTotalPkts: document.getElementById('dossierTotalPkts'),
  dossierAvgBytes: document.getElementById('dossierAvgBytes'),
  dossierSentPkts: document.getElementById('dossierSentPkts'),
  dossierUniqueDests: document.getElementById('dossierUniqueDests'),
  dossierRecvPkts: document.getElementById('dossierRecvPkts'),
  dossierUniqueSources: document.getElementById('dossierUniqueSources'),
  dossierTopProto: document.getElementById('dossierTopProto'),
  dossierProtoCount: document.getElementById('dossierProtoCount'),
  dossierTopDestsList: document.getElementById('dossierTopDestsList'),
  dossierTopSourcesList: document.getElementById('dossierTopSourcesList'),
  dossierProtoBars: document.getElementById('dossierProtoBars'),
  dossierAlertsList: document.getElementById('dossierAlertsList'),
  closeDossierBtn: document.getElementById('closeDossierBtn'),
  closeDossierBottomBtn: document.getElementById('closeDossierBottomBtn'),

  // Modal Guide
  toggleGuideBtn: document.getElementById('toggleGuideBtn'),
  analystGuideModal: document.getElementById('analystGuideModal'),
  closeGuideBtn: document.getElementById('closeGuideBtn'),
  closeGuideBottomBtn: document.getElementById('closeGuideBottomBtn')
};

// ==========================================================================
// IP Address Classification Helper (100% Client-Side, Zero External Calls)
// ==========================================================================

/**
 * Validates and classifies an IP address locally into standard network categories.
 */
function classifyIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return 'Unknown';
  const clean = ip.trim();

  // IPv4 check
  const v4Parts = clean.split('.');
  if (v4Parts.length === 4 && v4Parts.every(part => /^\d+$/.test(part))) {
    const [a, b, c, d] = v4Parts.map(n => parseInt(n, 10));
    if ([a, b, c, d].every(n => n >= 0 && n <= 255)) {
      // Loopback (127.0.0.0/8)
      if (a === 127) return 'Loopback';

      // Broadcast
      if (a === 255 && b === 255 && c === 255 && d === 255) return 'Broadcast';
      if (d === 255) return 'Broadcast';

      // Link-local / APIPA (169.254.0.0/16)
      if (a === 169 && b === 254) return 'Link-local';

      // Multicast (224.0.0.0 to 239.255.255.255)
      if (a >= 224 && a <= 239) return 'Multicast';

      // Private RFC 1918
      // 10.0.0.0/8
      if (a === 10) return 'Private RFC 1918';
      // 172.16.0.0/12
      if (a === 172 && b >= 16 && b <= 31) return 'Private RFC 1918';
      // 192.168.0.0/16
      if (a === 192 && b === 168) return 'Private RFC 1918';

      return 'Public/WAN';
    }
  }

  // IPv6 check
  if (clean.includes(':')) {
    const lower = clean.toLowerCase();
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'Loopback';
    if (lower.startsWith('fe80:')) return 'Link-local';
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'Private RFC 1918';
    if (lower.startsWith('ff')) return 'Multicast';
    return 'Public/WAN';
  }

  return 'Unknown';
}

/**
 * Checks if a string looks like a valid IP address.
 */
function isValidIp(str) {
  const cat = classifyIpAddress(str);
  return cat !== 'Unknown';
}

// ==========================================================================
// Resilient RFC-4180 Client-Side CSV Parser
// ==========================================================================

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

    if (['source', 'src', 'ip.src', 'sourceip', 'srcip', 'sourceaddress'].includes(clean)) {
      if (mapping.source === -1) mapping.source = index;
    } else if (['destination', 'dst', 'dest', 'ip.dst', 'destinationip', 'dstip', 'destinationaddress'].includes(clean)) {
      if (mapping.destination === -1) mapping.destination = index;
    } else if (['protocol', 'proto', 'ip.proto'].includes(clean)) {
      if (mapping.protocol === -1) mapping.protocol = index;
    } else if (['length', 'len', 'frame.len', 'framelength', 'bytes', 'packetlength'].includes(clean)) {
      if (mapping.length === -1) mapping.length = index;
    } else if (['info', 'information', 'summary', 'packetinfo'].includes(clean)) {
      if (mapping.info === -1) mapping.info = index;
    } else if (['time', 'timestamp', 'frame.time', 'time_relative'].includes(clean)) {
      if (mapping.time === -1) mapping.time = index;
    } else if (['no.', 'no', 'number', 'frame.number'].includes(clean)) {
      if (mapping.number === -1) mapping.number = index;
    }
  });

  return mapping;
}

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
  if (colMap.time === -1) missingOptional.push('Time (traffic timeline disabled)');

  // Build sanitized packets
  const packets = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const source = (row[colMap.source] || '').trim();
    const destination = (row[colMap.destination] || '').trim();

    if (!source && !destination) continue;

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
  elements.activeCaptureLabel.textContent = `${fileName} (${packets.length} pkts)`;

  populateProtocolFilterDropdown();
  runAnalysisAndRender();
}

function showIngestStatus(type, htmlMessage, isDemo = false) {
  elements.ingestStatus.className = `ingest-status ${type}`;
  elements.ingestStatus.classList.remove('hidden');

  let badge = isDemo ? '<span class="demo-active-badge">DEMO DATA</span>' : '';
  elements.ingestStatus.innerHTML = `<div>${badge} ${htmlMessage}</div>`;
}

// ==========================================================================
// Triage & Detection Rule Engine (Explainable, Rule-Based, Zero ML)
// ==========================================================================

function extractDestinationPort(infoStr) {
  if (!infoStr) return null;

  const arrowMatch = infoStr.match(/(?:->|>)\s*(\d+)/);
  if (arrowMatch) {
    const port = parseInt(arrowMatch[1], 10);
    if (port > 0 && port <= 65535) return port;
  }

  const explicitMatch = infoStr.match(/(?:destination\s*port|dst\s*port|dport)[:\s]+(\d+)/i);
  if (explicitMatch) {
    const port = parseInt(explicitMatch[1], 10);
    if (port > 0 && port <= 65535) return port;
  }

  return null;
}

function evaluateDetectionRules(packets, thresholds) {
  const alerts = [];
  let investigationScore = 0;
  const scoreBreakdown = [];

  const sourcePacketCounts = new Map();
  const sourceDestMap = new Map();
  const sourceDestPortsMap = new Map();
  const sourceIcmpCounts = new Map();
  const sourceDnsCounts = new Map();
  const conversationCounts = new Map();
  const sourceSynCounts = new Map();

  for (const pkt of packets) {
    const src = pkt.source;
    const dst = pkt.destination;
    const proto = pkt.protocol;
    const info = pkt.info;

    sourcePacketCounts.set(src, (sourcePacketCounts.get(src) || 0) + 1);

    if (!sourceDestMap.has(src)) sourceDestMap.set(src, new Set());
    sourceDestMap.get(src).add(dst);

    const destPort = extractDestinationPort(info);
    if (destPort) {
      const srcDestKey = `${src}->${dst}`;
      if (!sourceDestPortsMap.has(srcDestKey)) sourceDestPortsMap.set(srcDestKey, new Set());
      sourceDestPortsMap.get(srcDestKey).add(destPort);
    }

    if (proto === 'ICMP' || proto.includes('ICMP')) {
      sourceIcmpCounts.set(src, (sourceIcmpCounts.get(src) || 0) + 1);
    }

    if (proto === 'DNS' || proto.includes('DNS') || info.toLowerCase().includes('standard query')) {
      sourceDnsCounts.set(src, (sourceDnsCounts.get(src) || 0) + 1);
    }

    const convKey = `${src} -> ${dst}`;
    if (!conversationCounts.has(convKey)) {
      conversationCounts.set(convKey, { count: 0, protocols: new Map() });
    }
    const conv = conversationCounts.get(convKey);
    conv.count++;
    conv.protocols.set(proto, (conv.protocols.get(proto) || 0) + 1);

    if (proto === 'TCP' && info.includes('[SYN]') && !info.includes('[SYN, ACK]')) {
      sourceSynCounts.set(src, (sourceSynCounts.get(src) || 0) + 1);
    }
  }

  // RULE 1 — HIGH PACKET VOLUME
  sourcePacketCounts.forEach((count, source) => {
    if (count > thresholds.volume) {
      const sev = count > thresholds.volume * 2.5 ? 'MEDIUM' : 'LOW';
      const points = sev === 'MEDIUM' ? 25 : 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High Volume (${source})`);

      alerts.push({
        id: `rule1-${source}`,
        ruleId: 'RULE-1-HIGH-VOLUME',
        name: 'High Packet Volume',
        severity: sev,
        source: source,
        destination: null,
        activity: `${count} packets generated by host`,
        evidence: `${count} packets transmitted (Threshold: ${thresholds.volume})`,
        threshold: `Threshold: > ${thresholds.volume} packets`,
        explanation: 'A host generating significantly more traffic than expected may warrant investigation to determine if anomalous bulk transfer or automated processes are occurring.',
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
        ],
        wiresharkFilter: isValidIp(source) ? `ip.addr == ${source}` : null
      });
    }
  });

  // RULE 2 — POSSIBLE HOST SCANNING
  sourceDestMap.forEach((destSet, source) => {
    const uniqueDests = destSet.size;
    if (uniqueDests > thresholds.destinations) {
      const points = 25;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Possible Host Scan (${source})`);

      alerts.push({
        id: `rule2-${source}`,
        ruleId: 'RULE-2-HOST-SCAN',
        name: 'Possible Network Host Scanning',
        severity: 'MEDIUM',
        source: source,
        destination: `Multiple (${uniqueDests} unique targets)`,
        activity: `Transmitted traffic to ${uniqueDests} unique destination hosts`,
        evidence: `Communicated with ${uniqueDests} unique destination IP addresses (Threshold: ${thresholds.destinations})`,
        threshold: `Threshold: > ${thresholds.destinations} destinations`,
        explanation: 'A single host communicating with an unusually large number of destination systems over a brief capture window may indicate network reconnaissance or host discovery.',
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
        ],
        wiresharkFilter: isValidIp(source) ? `ip.src == ${source}` : null
      });
    }
  });

  // RULE 3 — POSSIBLE PORT SCANNING
  sourceDestPortsMap.forEach((portsSet, key) => {
    const portCount = portsSet.size;
    if (portCount > thresholds.ports) {
      const [src, dst] = key.split('->');
      const points = 25;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Possible Port Scan (${src} -> ${dst})`);

      alerts.push({
        id: `rule3-${key}`,
        ruleId: 'RULE-3-PORT-SCAN',
        name: 'Possible Port Scanning',
        severity: 'MEDIUM',
        source: src,
        destination: dst,
        activity: `Contacted ${portCount} unique destination ports on single target`,
        evidence: `Contacted ${portCount} distinct destination ports on ${dst} (Threshold: ${thresholds.ports})`,
        threshold: `Threshold: > ${thresholds.ports} unique ports`,
        explanation: 'Systematically probing numerous ports on a single host is a classic hallmark of service discovery or reconnaissance aimed at finding exposed services.',
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
        ],
        wiresharkFilter: (isValidIp(src) && isValidIp(dst)) ? `ip.src == ${src} && ip.dst == ${dst} && tcp.flags.syn == 1` : null
      });
    }
  });

  // RULE 4 — HIGH ICMP ACTIVITY
  sourceIcmpCounts.forEach((count, source) => {
    if (count > thresholds.icmp) {
      const points = 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High ICMP (${source})`);

      alerts.push({
        id: `rule4-${source}`,
        ruleId: 'RULE-4-HIGH-ICMP',
        name: 'High ICMP Activity',
        severity: 'LOW',
        source: source,
        destination: 'Various targets',
        activity: `Sent ${count} ICMP control packets`,
        evidence: `Sent ${count} ICMP packets (Threshold: ${thresholds.icmp})`,
        threshold: `Threshold: > ${thresholds.icmp} ICMP packets`,
        explanation: 'Unusually high volume of ICMP packets may indicate network ping sweeps, path MTU discovery probes, or automated reachability monitoring.',
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
        ],
        wiresharkFilter: isValidIp(source) ? `ip.src == ${source} && icmp` : null
      });
    }
  });

  // RULE 5 — HIGH DNS QUERY ACTIVITY
  sourceDnsCounts.forEach((count, source) => {
    if (count > thresholds.dns) {
      const points = 15;
      investigationScore += points;
      scoreBreakdown.push(`+${points} High DNS Activity (${source})`);

      alerts.push({
        id: `rule5-${source}`,
        ruleId: 'RULE-5-HIGH-DNS',
        name: 'High DNS Query Volume',
        severity: 'LOW',
        source: source,
        destination: 'DNS Resolvers',
        activity: `Generated ${count} DNS query packets`,
        evidence: `Sent ${count} DNS query/response packets (Threshold: ${thresholds.dns})`,
        threshold: `Threshold: > ${thresholds.dns} DNS packets`,
        explanation: 'Spikes in DNS query volume may signify aggressive domain lookups, automated crawlers, misconfigured caching, or potential DNS tunneling/beaconing.',
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
        ],
        wiresharkFilter: isValidIp(source) ? `ip.src == ${source} && udp.port == 53` : null
      });
    }
  });

  // RULE 6 — REPEATED SOURCE-TO-DESTINATION COMMUNICATION
  conversationCounts.forEach((data, convKey) => {
    if (data.count > thresholds.repeated) {
      const [src, dst] = convKey.split(' -> ');
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
        ruleId: 'RULE-6-REPEATED-TALKER',
        name: 'Repeated Host-to-Host Communication',
        severity: 'INFORMATIONAL',
        source: src,
        destination: dst,
        activity: `${data.count} packets exchanged (${topProto})`,
        evidence: `Exchanged ${data.count} packets with single destination (Threshold: ${thresholds.repeated})`,
        threshold: `Threshold: > ${thresholds.repeated} conversation packets`,
        explanation: 'Heavy one-to-one communication patterns indicate an active data channel. Analysts check these to verify whether large transfers or automated beaconing are legitimate.',
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
        ],
        wiresharkFilter: (isValidIp(src) && isValidIp(dst)) ? `ip.src == ${src} && ip.dst == ${dst}` : null
      });
    }
  });

  // RULE 7 — TCP SYN HEAVY ACTIVITY
  sourceSynCounts.forEach((count, source) => {
    if (count > thresholds.syn) {
      const points = 20;
      investigationScore += points;
      scoreBreakdown.push(`+${points} Heavy TCP SYN (${source})`);

      alerts.push({
        id: `rule7-${source}`,
        ruleId: 'RULE-7-SYN-BURST',
        name: 'TCP SYN Heavy Activity',
        severity: 'MEDIUM',
        source: source,
        destination: 'Various targets',
        activity: `Transmitted ${count} TCP SYN connection initiation packets`,
        evidence: `Transmitted ${count} TCP SYN packets without ACK (Threshold: ${thresholds.syn})`,
        threshold: `Threshold: > ${thresholds.syn} SYN packets`,
        explanation: 'A cluster of TCP SYN packets indicates repeated attempts to establish new connections. When frequent, it can correlate with port scanning or connection failure cascades.',
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
        ],
        wiresharkFilter: isValidIp(source) ? `ip.src == ${source} && tcp.flags.syn == 1` : null
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
// Host Dossier Compiler (100% Client-Side Intelligence)
// ==========================================================================

function compileHostDossier(targetIp, packets, alerts) {
  let sentPkts = 0;
  let recvPkts = 0;
  let totalBytes = 0;

  const destsMap = new Map();
  const sourcesMap = new Map();
  const protocolsMap = new Map();

  for (const pkt of packets) {
    const isSource = pkt.source === targetIp;
    const isDest = pkt.destination === targetIp;

    if (isSource) {
      sentPkts++;
      totalBytes += pkt.length;
      destsMap.set(pkt.destination, (destsMap.get(pkt.destination) || 0) + 1);
      protocolsMap.set(pkt.protocol, (protocolsMap.get(pkt.protocol) || 0) + 1);
    }
    if (isDest) {
      recvPkts++;
      totalBytes += pkt.length;
      sourcesMap.set(pkt.source, (sourcesMap.get(pkt.source) || 0) + 1);
      protocolsMap.set(pkt.protocol, (protocolsMap.get(pkt.protocol) || 0) + 1);
    }
  }

  const totalPkts = sentPkts + recvPkts;
  const avgBytes = totalPkts > 0 ? Math.round(totalBytes / totalPkts) : 0;

  let topProto = 'None';
  let maxProtoCount = 0;
  protocolsMap.forEach((count, p) => {
    if (count > maxProtoCount) {
      maxProtoCount = count;
      topProto = p;
    }
  });

  const topDests = Array.from(destsMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topSources = Array.from(sourcesMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Filter alerts where this IP was source or destination
  const hostAlerts = alerts.filter(a => a.source === targetIp || a.destination === targetIp);

  return {
    ip: targetIp,
    category: classifyIpAddress(targetIp),
    totalPackets: totalPkts,
    sentPackets: sentPkts,
    recvPackets: recvPkts,
    uniqueDests: destsMap.size,
    uniqueSources: sourcesMap.size,
    avgBytes,
    topProtocol: topProto,
    topProtoCount: maxProtoCount,
    protocolsMap,
    topDests,
    topSources,
    hostAlerts
  };
}

function openHostDossier(targetIp) {
  if (!targetIp || !elements.hostDossierModal) return;

  const dossier = compileHostDossier(targetIp, rawPackets, latestRuleResults.alerts);

  elements.dossierIpTitle.textContent = dossier.ip;

  // Category badge
  const cat = dossier.category;
  let catClass = 'cat-unknown';
  if (cat.includes('Private')) catClass = 'cat-private';
  else if (cat === 'Loopback') catClass = 'cat-loopback';
  else if (cat === 'Link-local') catClass = 'cat-linklocal';
  else if (cat === 'Multicast') catClass = 'cat-multicast';
  else if (cat === 'Broadcast') catClass = 'cat-broadcast';
  else if (cat === 'Public/WAN') catClass = 'cat-public';

  elements.dossierCategoryBadge.className = `badge badge-category ${catClass}`;
  elements.dossierCategoryBadge.textContent = cat;

  // Stats
  elements.dossierTotalPkts.textContent = dossier.totalPackets.toLocaleString();
  elements.dossierAvgBytes.textContent = `Avg Size: ${dossier.avgBytes} B`;
  elements.dossierSentPkts.textContent = dossier.sentPackets.toLocaleString();
  elements.dossierUniqueDests.textContent = `${dossier.uniqueDests} destinations`;
  elements.dossierRecvPkts.textContent = dossier.recvPackets.toLocaleString();
  elements.dossierUniqueSources.textContent = `${dossier.uniqueSources} sources`;
  elements.dossierTopProto.textContent = dossier.topProtocol;
  elements.dossierProtoCount.textContent = `${dossier.topProtoCount} packets`;

  // Top destinations
  elements.dossierTopDestsList.innerHTML = '';
  if (dossier.topDests.length === 0) {
    elements.dossierTopDestsList.innerHTML = '<span style="font-size:0.75rem; color:var(--text-dim);">No outbound packets recorded</span>';
  } else {
    dossier.topDests.forEach(([dest, cnt]) => {
      const item = document.createElement('div');
      item.className = 'dossier-list-item';
      item.innerHTML = `
        <span class="item-addr">${renderInteractiveIp(dest)}</span>
        <span class="item-count">${cnt.toLocaleString()} pkts</span>
      `;
      elements.dossierTopDestsList.appendChild(item);
    });
  }

  // Top sources
  elements.dossierTopSourcesList.innerHTML = '';
  if (dossier.topSources.length === 0) {
    elements.dossierTopSourcesList.innerHTML = '<span style="font-size:0.75rem; color:var(--text-dim);">No inbound packets recorded</span>';
  } else {
    dossier.topSources.forEach(([src, cnt]) => {
      const item = document.createElement('div');
      item.className = 'dossier-list-item';
      item.innerHTML = `
        <span class="item-addr">${renderInteractiveIp(src)}</span>
        <span class="item-count">${cnt.toLocaleString()} pkts</span>
      `;
      elements.dossierTopSourcesList.appendChild(item);
    });
  }

  // Protocol bars
  elements.dossierProtoBars.innerHTML = '';
  const sortedProtos = Array.from(dossier.protocolsMap.entries()).sort((a, b) => b[1] - a[1]);
  if (sortedProtos.length === 0) {
    elements.dossierProtoBars.innerHTML = '<span style="font-size:0.75rem; color:var(--text-dim);">No protocol records</span>';
  } else {
    sortedProtos.forEach(([proto, count]) => {
      const pct = dossier.totalPackets > 0 ? ((count / dossier.totalPackets) * 100).toFixed(1) : 0;
      const cleanProto = proto.toUpperCase().replace(/[^A-Z]/g, '');
      const row = document.createElement('div');
      row.className = 'proto-bar-row';
      row.innerHTML = `
        <div class="proto-bar-labels">
          <span class="proto-bar-name">${escapeHtml(proto)}</span>
          <span class="proto-bar-stats">${count} pkts (${pct}%)</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill proto-${cleanProto}" style="width: ${pct}%"></div>
        </div>
      `;
      elements.dossierProtoBars.appendChild(row);
    });
  }

  // Host alerts
  elements.dossierAlertsList.innerHTML = '';
  if (dossier.hostAlerts.length === 0) {
    elements.dossierAlertsList.innerHTML = '<span style="font-size:0.78rem; color:var(--text-dim);">No triage alerts triggered for this host.</span>';
  } else {
    dossier.hostAlerts.forEach(alert => {
      const row = document.createElement('div');
      row.className = 'dossier-alert-row';
      row.innerHTML = `
        <div>
          <span class="badge-sev sev-${alert.severity.toLowerCase()}">${alert.severity}</span>
          <strong class="dossier-alert-name" style="margin-left:6px;">${escapeHtml(alert.name)}</strong>
          <div class="dossier-alert-evidence">${escapeHtml(alert.evidence)}</div>
        </div>
      `;
      elements.dossierAlertsList.appendChild(row);
    });
  }

  elements.hostDossierModal.classList.remove('hidden');
}

function closeHostDossier() {
  if (elements.hostDossierModal) {
    elements.hostDossierModal.classList.add('hidden');
  }
}

// ==========================================================================
// Traffic Density Timeline (Pure Native SVG, Zero Charting Dependencies)
// ==========================================================================

function parseTimestampsAndRenderTimeline(packets) {
  const container = elements.timelineContainer;
  const fallback = elements.timelineFallback;
  const badge = elements.timelineSpanBadge;

  container.innerHTML = '';

  const parsedTimes = [];
  for (const pkt of packets) {
    if (!pkt.time) continue;
    const trimmed = pkt.time.trim();
    // Try float seconds
    const num = parseFloat(trimmed);
    if (!isNaN(num) && isFinite(num)) {
      parsedTimes.push(num);
    } else {
      // Try date parse
      const parsedDate = Date.parse(trimmed);
      if (!isNaN(parsedDate)) {
        parsedTimes.push(parsedDate / 1000); // convert ms to seconds
      }
    }
  }

  // Require at least 2 parseable timestamps
  if (parsedTimes.length < 2) {
    container.classList.add('hidden');
    fallback.classList.remove('hidden');
    badge.textContent = 'No Timestamps';
    return;
  }

  const minTime = Math.min(...parsedTimes);
  const maxTime = Math.max(...parsedTimes);
  const duration = maxTime - minTime;

  // Fallback if timestamps are all identical
  if (duration <= 0) {
    container.classList.add('hidden');
    fallback.classList.remove('hidden');
    badge.textContent = 'Instantaneous';
    return;
  }

  container.classList.remove('hidden');
  fallback.classList.add('hidden');

  const formattedSpan = duration >= 60 ? `${(duration / 60).toFixed(1)} mins` : `${duration.toFixed(3)}s`;
  badge.textContent = `Span: ${formattedSpan} (${minTime.toFixed(3)}s to ${maxTime.toFixed(3)}s)`;

  // Divide into buckets (16 buckets)
  const numBuckets = 16;
  const bucketCounts = new Array(numBuckets).fill(0);
  const bucketDuration = duration / numBuckets;

  for (const t of parsedTimes) {
    const idx = Math.min(numBuckets - 1, Math.floor((t - minTime) / bucketDuration));
    bucketCounts[idx]++;
  }

  const maxBucketCount = Math.max(...bucketCounts, 1);

  // SVG parameters
  const svgWidth = 760;
  const svgHeight = 110;
  const padLeft = 45;
  const padRight = 20;
  const padBottom = 26;
  const padTop = 15;
  const chartWidth = svgWidth - padLeft - padRight;
  const chartHeight = svgHeight - padTop - padBottom;
  const barSpacing = 4;
  const totalSpacing = (numBuckets - 1) * barSpacing;
  const barWidth = Math.max(2, (chartWidth - totalSpacing) / numBuckets);

  let barsSvg = '';
  for (let i = 0; i < numBuckets; i++) {
    const count = bucketCounts[i];
    const barHeight = Math.max(3, Math.round((count / maxBucketCount) * chartHeight));
    const x = padLeft + i * (barWidth + barSpacing);
    const y = padTop + chartHeight - barHeight;
    const bStart = (minTime + i * bucketDuration).toFixed(3);
    const bEnd = (minTime + (i + 1) * bucketDuration).toFixed(3);

    barsSvg += `
      <g>
        <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="2" fill="#3b82f6" opacity="0.85">
          <title>Time: ${bStart}s - ${bEnd}s | Packets: ${count}</title>
        </rect>
        <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="2" fill="none" stroke="#60a5fa" stroke-width="0.75" />
      </g>
    `;
  }

  const svgMarkup = `
    <svg viewBox="0 0 ${svgWidth} ${svgHeight}" width="100%" height="110" preserveAspectRatio="none" style="display:block;">
      <!-- Baseline axis -->
      <line x1="${padLeft}" y1="${padTop + chartHeight}" x2="${padLeft + chartWidth}" y2="${padTop + chartHeight}" stroke="#233044" stroke-width="1.5" />

      <!-- Peak indicator line & label -->
      <line x1="${padLeft}" y1="${padTop}" x2="${padLeft + chartWidth}" y2="${padTop}" stroke="#1e293b" stroke-dasharray="3,3" stroke-width="1" />
      <text x="${padLeft - 6}" y="${padTop + 4}" fill="#64748b" font-size="10" font-family="ui-monospace, monospace" text-anchor="end">${maxBucketCount} pkts</text>
      <text x="${padLeft - 6}" y="${padTop + chartHeight + 2}" fill="#64748b" font-size="10" font-family="ui-monospace, monospace" text-anchor="end">0</text>

      <!-- Bars -->
      ${barsSvg}

      <!-- Start and End axis labels -->
      <text x="${padLeft}" y="${svgHeight - 6}" fill="#94a3b8" font-size="10" font-family="ui-monospace, monospace">Start: ${minTime.toFixed(3)}s</text>
      <text x="${padLeft + chartWidth}" y="${svgHeight - 6}" fill="#94a3b8" font-size="10" font-family="ui-monospace, monospace" text-anchor="end">End: ${maxTime.toFixed(3)}s</text>
    </svg>
  `;

  container.innerHTML = svgMarkup;
}

// ==========================================================================
// Export SOC Triage Incident Report (Browser-Generated Markdown)
// ==========================================================================

function generateTriageMarkdownReport(captureInfo, packets, ruleResults, thresholds) {
  const activeThresholds = thresholds || currentThresholds || DEFAULT_THRESHOLDS;
  const dateStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const isDemo = captureInfo.isDemo ? 'Demo Simulated Capture' : 'Live Capture Ingestion';
  const fileName = captureInfo.fileName || 'capture.csv';

  // Protocols summary
  const protoMap = new Map();
  for (const p of packets) {
    protoMap.set(p.protocol, (protoMap.get(p.protocol) || 0) + 1);
  }
  const protoList = Array.from(protoMap.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([proto, count]) => `- **${proto}**: ${count} packets (${((count / packets.length) * 100).toFixed(1)}%)`)
    .join('\n');

  // Classification label
  let classification = 'Baseline Traffic (Routine)';
  if (ruleResults.score >= 60) classification = 'Notable Priority (Requires Review)';
  else if (ruleResults.score >= 30) classification = 'Elevated Activity (Routine Triage)';

  // Alerts section
  let findingsSection = '';
  if (ruleResults.alerts.length === 0) {
    findingsSection = `### Zero Anomalous Alerts Triggered\n\nAll packet counts and communication patterns are currently within configured baseline thresholds. No investigative findings were generated under the current rule configuration.\n`;
  } else {
    findingsSection = ruleResults.alerts.map((alert, index) => {
      const benignItems = alert.benignExplanations.map(b => `  - ${b}`).join('\n');
      const stepsItems = alert.suggestedInvestigation.map(s => `  1. ${s}`).join('\n');
      const filterLine = alert.wiresharkFilter
        ? `\n- **Suggested Wireshark Filter:** \`${alert.wiresharkFilter}\``
        : `\n- **Suggested Wireshark Filter:** *Unavailable (required packet fields missing in CSV)*`;

      return `#### Finding ${index + 1}: ${alert.name} [${alert.severity}]
- **Rule Identifier:** \`${alert.ruleId}\`
- **Source Host:** \`${alert.source}\`
- **Destination Host:** \`${alert.destination || 'Various'}\`
- **Observed Evidence:** ${alert.evidence}
- **Configured Threshold:** ${alert.threshold}${filterLine}

**Why This Activity Deserves Investigation:**  
${alert.whyMatters}

**Possible Benign Explanations:**  
${benignItems}

**Recommended SOC Investigation Steps:**  
${stepsItems}
`;
    }).join('\n---\n\n');
  }

  return `# Security Operations Center (SOC) Triage Report
**Network Traffic Anomaly & Investigation Triage Assessment**

---

## 1. Executive Summary

| Parameter | Value |
| :--- | :--- |
| **Report Generated** | ${dateStr} |
| **Ingested Capture File** | \`${fileName}\` |
| **Data Classification** | ${isDemo} |
| **Total Packets Ingested** | ${packets.length.toLocaleString()} |
| **Unique Source Hosts** | ${new Set(packets.map(p => p.source)).size} |
| **Unique Destination Hosts** | ${new Set(packets.map(p => p.destination)).size} |
| **Investigation Triage Score** | **${ruleResults.score} / 100** |
| **Triage Classification** | **${classification}** |

> [!IMPORTANT]
> **Mandatory Analyst Disclaimer:**  
> Alerts indicate activity worth investigating and do not prove malicious behaviour.  
> Only analyse traffic from systems and networks you own or are authorised to monitor.

---

## 2. Ingested Protocol Distribution

${protoList}

---

## 3. Active Rule Thresholds Configured

- **Rule 1 (Packets per Source):** > ${activeThresholds.volume} packets
- **Rule 2 (Unique Destinations / Host Scan):** > ${activeThresholds.destinations} targets
- **Rule 3 (Unique Ports / Port Scan):** > ${activeThresholds.ports} destination ports
- **Rule 4 (ICMP Packets per Source):** > ${activeThresholds.icmp} packets
- **Rule 5 (DNS Queries per Source):** > ${activeThresholds.dns} packets
- **Rule 6 (Repeated Source-to-Destination):** > ${activeThresholds.repeated} conversation packets
- **Rule 7 (Heavy TCP SYN initiation):** > ${activeThresholds.syn} SYN packets

---

## 4. Triage Findings & Evidence

${findingsSection}

---

## 5. Recommended Tier-2 Next Actions

1. **Verify Source Attribution:** Cross-reference flagged source IPs against enterprise DHCP leases, asset management databases, and Active Directory computer accounts.
2. **Review Host Context:** Check whether flagged endpoints are running scheduled backups, administrative inventory scanners, or developer test scripts.
3. **Inspect Full Payload:** If anomalies remain unexplained, obtain the full raw \`.pcap\` capture to inspect deep payload bytes, certificates, and application-layer protocols.
4. **Correlate Telemetry:** Check endpoint EDR (CrowdStrike/Defender/Sysmon) process execution logs matching the capture timeframe.

---
*Generated client-side by Network Traffic Triage Tool (net-triage) &bull; Zero external data transmission.*
`;
}

function exportTriageReport() {
  if (rawPackets.length === 0) return;

  const captureInfo = {
    fileName: currentFileName || 'capture.csv',
    isDemo: isDemoData
  };

  const markdownContent = generateTriageMarkdownReport(
    captureInfo,
    rawPackets,
    latestRuleResults,
    currentThresholds
  );

  const cleanName = (currentFileName || 'capture').replace(/[^a-zA-Z0-9_-]/g, '_');
  const downloadFileName = `triage-report-${cleanName}-${Date.now()}.md`;

  const blob = new Blob([markdownContent], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = downloadFileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ==========================================================================
// Dashboard Analysis, Aggregation & Rendering
// ==========================================================================

function renderInteractiveIp(ip) {
  if (!ip) return 'Unknown';
  return `<button type="button" class="ip-interactive" data-ip="${escapeHtml(ip)}" title="Click to view Host Dossier for ${escapeHtml(ip)}">${escapeHtml(ip)}</button>`;
}

function runAnalysisAndRender() {
  if (rawPackets.length === 0) return;

  // 1. Detection Rules Evaluation
  latestRuleResults = evaluateDetectionRules(rawPackets, currentThresholds);

  // 2. Metrics Aggregations
  let totalBytes = 0;
  const sourcesMap = new Map();
  const destsMap = new Map();
  const protocolsMap = new Map();
  const conversationsMap = new Map();

  for (const pkt of rawPackets) {
    totalBytes += pkt.length;
    sourcesMap.set(pkt.source, (sourcesMap.get(pkt.source) || 0) + 1);
    destsMap.set(pkt.destination, (destsMap.get(pkt.destination) || 0) + 1);
    protocolsMap.set(pkt.protocol, (protocolsMap.get(pkt.protocol) || 0) + 1);

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

  let topSource = 'None';
  let maxSourceCount = 0;
  sourcesMap.forEach((count, src) => {
    if (count > maxSourceCount) {
      maxSourceCount = count;
      topSource = src;
    }
  });

  let topDest = 'None';
  let maxDestCount = 0;
  destsMap.forEach((count, dst) => {
    if (count > maxDestCount) {
      maxDestCount = count;
      topDest = dst;
    }
  });

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
  elements.statTopSource.innerHTML = `Top: ${renderInteractiveIp(topSource)} (${maxSourceCount} pkts)`;

  elements.statUniqueDests.textContent = destsMap.size.toLocaleString();
  elements.statTopDest.innerHTML = `Top: ${renderInteractiveIp(topDest)} (${maxDestCount} pkts)`;

  elements.statTopProtocol.textContent = topProtocol;
  elements.statProtocolCount.textContent = `${maxProtoCount.toLocaleString()} packets (${Math.round((maxProtoCount / rawPackets.length) * 100)}%)`;

  // Render Investigation Score
  renderInvestigationScore(latestRuleResults.score, latestRuleResults.breakdown);

  // Render Traffic Timeline
  parseTimestampsAndRenderTimeline(rawPackets);

  // Render Alerts
  renderAlerts(latestRuleResults.alerts);

  // Render Visual Protocol Bars
  renderProtocolBars(protocolsMap, rawPackets.length);

  // Render Top Sources Table
  renderTopSources(sourcesMap, rawPackets.length);

  // Render Top Destinations Table
  renderTopDestinations(destsMap, rawPackets.length);

  // Render Top Conversations Table
  renderTopConversations(conversationsMap);

  // Render Packet Preview Table
  renderFilteredPacketPreview();
}

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

    // Wireshark display filter section
    let filterBlockHtml = '';
    if (alert.wiresharkFilter) {
      filterBlockHtml = `
        <div class="wireshark-filter-box">
          <div class="filter-header-row">
            <span class="filter-header-label">Investigative Wireshark Display Filter</span>
            <span class="filter-notice-text">Generated from the evidence available in this CSV.</span>
          </div>
          <div class="wireshark-code-row">
            <code class="filter-code-text">${escapeHtml(alert.wiresharkFilter)}</code>
            <button type="button" class="btn-copy-filter" data-filter="${escapeHtml(alert.wiresharkFilter)}">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
              <span>Copy Filter</span>
            </button>
          </div>
        </div>
      `;
    } else {
      filterBlockHtml = `
        <div class="wireshark-filter-box">
          <span class="filter-unavailable-notice">Wireshark filter unavailable because the required packet fields were not present in this CSV.</span>
        </div>
      `;
    }

    const destDisplay = alert.destination
      ? (isValidIp(alert.destination) ? renderInteractiveIp(alert.destination) : escapeHtml(alert.destination))
      : 'Various';

    card.innerHTML = `
      <div class="alert-top">
        <div class="alert-title-row">
          <span class="badge-sev sev-${alert.severity.toLowerCase()}">${alert.severity}</span>
          <h3 class="alert-name">${escapeHtml(alert.name)}</h3>
        </div>
        <div class="alert-hosts-meta">
          Source: ${renderInteractiveIp(alert.source)} | Destination: ${destDisplay}
        </div>
      </div>

      <div class="alert-evidence-grid">
        <div class="evidence-item">
          <strong>Observed Evidence</strong>
          <span>${escapeHtml(alert.evidence)}</span>
        </div>
        <div class="evidence-item">
          <strong>Configured Rule Parameter</strong>
          <span>${escapeHtml(alert.threshold)}</span>
        </div>
      </div>

      ${filterBlockHtml}

      <div class="alert-sections-grid">
        <div class="alert-block">
          <h4>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
            Why This Activity Could Matter
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

function renderProtocolBars(protocolsMap, totalPackets) {
  const container = elements.protocolBarsContainer;
  container.innerHTML = '';

  const sorted = Array.from(protocolsMap.entries()).sort((a, b) => b[1] - a[1]);

  sorted.forEach(([proto, count]) => {
    const pct = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;
    const row = document.createElement('div');
    row.className = 'proto-bar-row';
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
      <td class="cell-mono">${renderInteractiveIp(src)}</td>
      <td>${count.toLocaleString()}</td>
      <td>${pct}%</td>
    `;
    tbody.appendChild(tr);
  });
}

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
      <td class="cell-mono">${renderInteractiveIp(dst)}</td>
      <td>${count.toLocaleString()}</td>
      <td>${pct}%</td>
    `;
    tbody.appendChild(tr);
  });
}

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
      <td class="cell-mono">${renderInteractiveIp(conv.source)}</td>
      <td class="cell-mono">${renderInteractiveIp(conv.destination)}</td>
      <td>${conv.count.toLocaleString()}</td>
      <td><span class="badge badge-subtle">${escapeHtml(topProto)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

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
      <td class="cell-mono">${renderInteractiveIp(pkt.source)}</td>
      <td class="cell-mono">${renderInteractiveIp(pkt.destination)}</td>
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

  // 3. Export Triage Report Button
  elements.exportReportBtn.addEventListener('click', () => {
    exportTriageReport();
  });

  // 4. Threshold Configuration Accordion
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

  // 5. Severity Alert Filter
  elements.severityFilter.addEventListener('change', (e) => {
    activeFilter.severity = e.target.value;
    renderAlerts(latestRuleResults.alerts);
  });

  // 6. Interactive Table & Search Filters
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

  // 7. Interactive IP Click Listener (Event Delegation across entire document)
  document.addEventListener('click', (e) => {
    const ipBtn = e.target.closest('.ip-interactive');
    if (ipBtn) {
      const ip = ipBtn.getAttribute('data-ip');
      if (ip) {
        openHostDossier(ip);
      }
      return;
    }

    // Wireshark Filter Copy Button Delegation
    const copyBtn = e.target.closest('.btn-copy-filter');
    if (copyBtn) {
      const filterText = copyBtn.getAttribute('data-filter');
      if (filterText) {
        copyWiresharkFilter(filterText, copyBtn);
      }
    }
  });

  // Keyboard Enter on interactive IP
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const ipBtn = document.activeElement && document.activeElement.closest('.ip-interactive');
      if (ipBtn) {
        const ip = ipBtn.getAttribute('data-ip');
        if (ip) openHostDossier(ip);
      }
    }
  });

  // 8. Host Dossier Modal Close Listeners
  elements.closeDossierBtn.addEventListener('click', closeHostDossier);
  elements.closeDossierBottomBtn.addEventListener('click', closeHostDossier);
  elements.hostDossierModal.addEventListener('click', (e) => {
    if (e.target === elements.hostDossierModal) closeHostDossier();
  });

  // 9. Educational Analyst Guide Modal
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
    if (e.key === 'Escape') {
      if (!elements.hostDossierModal.classList.contains('hidden')) {
        closeHostDossier();
      } else if (!elements.analystGuideModal.classList.contains('hidden')) {
        closeGuide();
      }
    }
  });
}

/**
 * Copies a Wireshark filter string to the clipboard with clear UI feedback.
 */
function copyWiresharkFilter(filterString, buttonElement) {
  if (!filterString) return;

  const performFeedback = () => {
    const originalHtml = buttonElement.innerHTML;
    buttonElement.classList.add('copied');
    buttonElement.innerHTML = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
      <span>Filter copied.</span>
    `;

    setTimeout(() => {
      buttonElement.classList.remove('copied');
      buttonElement.innerHTML = originalHtml;
    }, 2000);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(filterString).then(performFeedback).catch(() => {
      fallbackCopyText(filterString);
      performFeedback();
    });
  } else {
    fallbackCopyText(filterString);
    performFeedback();
  }
}

/**
 * Compatibility fallback for copy text in constrained local browser contexts.
 */
function fallbackCopyText(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.top = '0';
  textarea.style.left = '0';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    document.execCommand('copy');
  } catch (err) {
    // Ignore copy error
  }
  document.body.removeChild(textarea);
}

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
