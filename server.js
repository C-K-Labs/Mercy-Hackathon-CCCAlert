require('dotenv').config();
const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const Database = require('better-sqlite3');
const ffmpeg = require('fluent-ffmpeg');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Notification dependencies (optional) ─────────────────────────────────
let twilioClient = null;
if (
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN &&
  !process.env.TWILIO_ACCOUNT_SID.includes('your_')
) {
  try {
    const twilio = require('twilio');
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  } catch (err) {
    console.warn('[notifier] Twilio load failed — skipping:', err.message);
  }
}

let resendClient = null;
if (process.env.RESEND_API_KEY) {
  try {
    const { Resend } = require('resend');
    resendClient = new Resend(process.env.RESEND_API_KEY);
  } catch (err) {
    console.warn('[notifier] Resend load failed — skipping:', err.message);
  }
}

const app = express();
app.use(express.json({ limit: '50mb' }));
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; script-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const CONFIDENCE_SCALE = 26;

// ─── Database setup ────────────────────────────────────────────────────────
const db = new Database('security.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS archived_incidents (
    id TEXT PRIMARY KEY,
    original_id TEXT,
    label TEXT,
    timestamp TEXT,
    location TEXT,
    confidence REAL,
    severity TEXT,
    priority TEXT,
    recommended_action TEXT,
    incident_status TEXT,
    operator_notes TEXT,
    source TEXT,
    source_key TEXT,
    urgency_score INTEGER,
    metadata TEXT,
    timeline TEXT,
    archived_at TEXT,
    archive_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT,
    first_seen TEXT,
    last_seen TEXT,
    last_camera TEXT,
    times_seen INTEGER DEFAULT 1,
    flagged INTEGER DEFAULT 0,
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER,
    camera_id TEXT,
    timestamp TEXT,
    incident INTEGER DEFAULT 0,
    severity TEXT,
    description TEXT,
    is_return INTEGER DEFAULT 0,
    FOREIGN KEY(person_id) REFERENCES people(id)
  );

  CREATE TABLE IF NOT EXISTS restricted_zones (
    camera_id TEXT PRIMARY KEY
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id TEXT,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    person_ids TEXT,
    timestamp TEXT,
    webhook_sent INTEGER DEFAULT 0,
    source TEXT
  );
`);

// Add classification columns to alerts if they do not exist yet (safe for existing DBs)
const alertColumns = db.prepare("PRAGMA table_info(alerts)").all().map(c => c.name);

const newColumns = [
  { name: 'urgency_score',      def: 'INTEGER DEFAULT 0'   },
  { name: 'priority',           def: "TEXT DEFAULT 'Low'"  },
  { name: 'recommended_action', def: "TEXT DEFAULT 'Log'"  },
  { name: 'incident_status',    def: "TEXT DEFAULT 'New'"  },
  { name: 'operator_notes',     def: "TEXT DEFAULT ''"     },
  { name: 'metadata_json',      def: "TEXT DEFAULT '{}'"   },
  { name: 'timeline_json',      def: "TEXT DEFAULT '[]'"   },
  { name: 'incident_uuid',      def: "TEXT DEFAULT ''"     },
];

for (const col of newColumns) {
  if (!alertColumns.includes(col.name)) {
    db.exec(`ALTER TABLE alerts ADD COLUMN ${col.name} ${col.def}`);
  }
}

// ─── Camera state ──────────────────────────────────────────────────────────
const cameraFeeds = {};

// ─── Classification constants ──────────────────────────────────────────────
const STATUSES = ['New', 'Reviewing', 'Escalated', 'Closed', 'False Positive'];
const PRIORITIES = { Low: 1, Medium: 2, High: 3 };
const SEVERITIES = { Low: 1, Moderate: 2, High: 3, Critical: 4 };

// Track notification history to avoid duplicate alerts
const notifiedUuids = new Set();

// ─── XML escaping for TwiML ───────────────────────────────────────────────
function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ─── Classification helpers ────────────────────────────────────────────────
function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function toIsoString(value) {
  const date = new Date(value || Date.now());
  return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
}

function ensureArray(value) {
  return Array.isArray(value) ? value : [];
}

function titleCaseSeverity(value) {
  const upper = String(value || '').toUpperCase();
  if (upper === 'CRITICAL') return 'Critical';
  if (upper === 'HIGH') return 'High';
  if (upper === 'MODERATE' || upper === 'MEDIUM') return 'Moderate';
  return 'Low';
}

function getThreatWeight(label) {
  const lower = String(label || '').toLowerCase();
  if (
    lower.includes('eating') || lower.includes('sitting') || lower.includes('walking') ||
    lower.includes('talking') || lower.includes('reading') || lower.includes('working') ||
    lower.includes('studying') || lower.includes('standing') || lower.includes('looking') ||
    lower.includes('watching')
  ) return 0;
  if (lower.includes('altercation') || lower.includes('fight')) return 38;
  if (lower.includes('weapon') || lower.includes('gun')) return 42;
  if (lower.includes('fire')) return 34;
  if (lower.includes('medical')) return 28;
  if (lower.includes('unauthorized') || lower.includes('forced') || lower.includes('breach')) return 30;
  if (lower.includes('suspicious') || lower.includes('disturbance')) return 22;
  return 5;
}

function getRecencyWeight(timestamp) {
  const ageMinutes = (Date.now() - new Date(timestamp).getTime()) / 60000;
  if (ageMinutes <= 2) return 18;
  if (ageMinutes <= 10) return 12;
  if (ageMinutes <= 30) return 7;
  return 2;
}

function mapScoreToSeverity(score) {
  if (score >= 90) return 'Critical';
  if (score >= 64) return 'High';
  if (score >= 38) return 'Moderate';
  return 'Low';
}

function mapScoreToPriority(score) {
  if (score >= 78) return 'High';
  if (score >= 42) return 'Medium';
  return 'Low';
}

function getRecommendedAction(priority) {
  if (priority === 'High') return 'Contact Police';
  if (priority === 'Medium') return 'Contact Security';
  return 'Log';
}

function buildLabel(description, fallback) {
  const text = String(description || fallback || '').trim();
  if (!text) return 'Campus incident alert';
  if (/altercation|fight/i.test(text)) return 'Physical altercation detected';
  if (/weapon|armed/i.test(text)) return 'Possible weapon-related incident';
  if (/medical/i.test(text)) return 'Medical emergency reported';
  if (/door|breach|forced/i.test(text)) return 'Possible unauthorized access';
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function buildPersonNotes(people) {
  return ensureArray(people)
    .map((person) => {
      const parts = [];
      if (person.description) parts.push(person.description);
      if (person.is_return) parts.push('returning individual');
      if (Number.isFinite(person.times_seen)) parts.push(`seen ${person.times_seen} times`);
      if (parts.length === 0) return '';
      return `Person ${person.person_id ?? 'unknown'}: ${parts.join(', ')}.`;
    })
    .filter(Boolean)
    .join(' ');
}

function buildSummary({ label, location, confidence, priority, repeatedLocationCount, crossCamera, source }) {
  const certainty =
    confidence >= 0.9
      ? 'Signal confidence is strong.'
      : confidence >= 0.75
        ? 'Signal confidence is moderate.'
        : 'Signal confidence is limited.';

  const reviewRecommended =
    confidence < 0.88 || priority !== 'Low' || repeatedLocationCount > 0 || crossCamera;

  if (source === 'EMERGENCY' || location === 'EMERGENCY') {
    return `An emergency alert was triggered via the Emergency button. ${certainty}${reviewRecommended ? ' Human review recommended.' : ''}`;
  }

  let firstSentence = `${label} was reported near ${location}.`;
  if (/altercation/i.test(label)) firstSentence = `A possible physical confrontation was reported near ${location}.`;
  if (/weapon/i.test(label)) firstSentence = `A possible weapon-related threat was reported near ${location}.`;
  if (/medical/i.test(label)) firstSentence = `A possible medical emergency was reported near ${location}.`;

  return `${firstSentence} ${certainty}${reviewRecommended ? ' Human review recommended.' : ''}`;
}

function createTimelineEntry(type, message, timestamp) {
  return {
    id: crypto.randomUUID(),
    type,
    message,
    timestamp: toIsoString(timestamp),
  };
}

// Count active alerts at the same location from DB (excludes Closed/False Positive)
function getRepeatedLocationCount(location, excludeUuid) {
  const rows = db.prepare(
    `SELECT incident_uuid FROM alerts WHERE camera_id = ? AND incident_status NOT IN ('Closed', 'False Positive')`
  ).all(location);
  return rows.filter(r => r.incident_uuid !== excludeUuid).length;
}

// ─── Core classification function ─────────────────────────────────────────
function classifyIncident({
  cameraId,
  description,
  timestamp,
  confidence,
  people,
  crossCamera,
  crossCameraNote,
  snapshotBase64,
  upstreamSeverity,
  source,
  userLocation,
  reporterName,
}) {
  const uuid = crypto.randomUUID();
  const ts = toIsoString(timestamp);
  const label = buildLabel(description, 'Campus incident alert');
  const conf = clamp(Number(confidence) || 0, 0, 1);

  const peopleArr = ensureArray(people);
  const hasCrossCamera = Boolean(crossCamera);
  const crossNote = crossCameraNote || '';
  const returningPersonWeight = peopleArr.some(p => p.is_return) ? 6 : 0;

  const threatWeight = getThreatWeight(label);
  const confidenceWeight = Math.round(conf * CONFIDENCE_SCALE);
  const repeatedLocationCount = getRepeatedLocationCount(cameraId, uuid);
  const repeatWeight = Math.min(repeatedLocationCount * 8, 24);
  const recencyWeight = getRecencyWeight(ts);
  const crossCameraWeight = hasCrossCamera ? 10 : 0;

  const score = clamp(
    threatWeight + confidenceWeight + repeatWeight + recencyWeight + crossCameraWeight + returningPersonWeight,
    0,
    100
  );

  const severity = mapScoreToSeverity(score);
  const priority = mapScoreToPriority(score);
  const recommendedAction = getRecommendedAction(priority);

  const summary = buildSummary({
    label,
    location: cameraId,
    confidence: conf,
    priority,
    repeatedLocationCount,
    crossCamera: hasCrossCamera,
    source,
  });

  const metadata = {
    alertType: 'INCIDENT',
    cameraId,
    description,
    people: peopleArr,
    crossCamera: hasCrossCamera,
    crossCameraNote: crossNote,
    snapshotBase64: snapshotBase64 || '',
    upstreamSeverity: upstreamSeverity || titleCaseSeverity(upstreamSeverity),
    userLocation: userLocation || null,
    reporterName: reporterName || 'Guest',
    scoring: {
      threatWeight,
      confidenceWeight,
      repeatedLocationCount,
      recencyWeight,
      crossCameraWeight,
      returningPersonWeight,
    },
  };

  const timeline = [
    createTimelineEntry(source || 'server', `Incident received from ${cameraId}.`, ts),
    ...(crossNote ? [createTimelineEntry('cross-camera', crossNote, ts)] : []),
  ];

  return {
    uuid,
    label,
    timestamp: ts,
    location: cameraId,
    confidence: conf,
    severity,
    priority,
    recommendedAction,
    summary,
    urgencyScore: score,
    metadata,
    timeline,
  };
}

// ─── Alert logger with classification ─────────────────────────────────────
function logAlert(cameraId, alertType, severity, description, personIds = [], source = null, classifyOptions = {}) {
  const classified = classifyIncident({
    cameraId,
    description,
    timestamp: classifyOptions.timestamp || new Date().toISOString(),
    confidence: classifyOptions.confidence,
    people: classifyOptions.people || [],
    crossCamera: classifyOptions.crossCamera || false,
    crossCameraNote: classifyOptions.crossCameraNote || '',
    snapshotBase64: classifyOptions.snapshotBase64 || '',
    upstreamSeverity: severity,
    source,
    userLocation: classifyOptions.userLocation || null,
    reporterName: classifyOptions.reporterName || 'Guest',
  });

  const result = db.prepare(`
    INSERT INTO alerts (
      camera_id, alert_type, severity, description, person_ids, timestamp, webhook_sent, source,
      urgency_score, priority, recommended_action, incident_status, operator_notes,
      metadata_json, timeline_json, incident_uuid
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    cameraId,
    alertType,
    classified.severity,
    description,
    JSON.stringify(personIds),
    classified.timestamp,
    0,
    source,
    classified.urgencyScore,
    classified.priority,
    classified.recommendedAction,
    'New',
    '',
    JSON.stringify(classified.metadata),
    JSON.stringify(classified.timeline),
    classified.uuid
  );

  const savedAlert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(result.lastInsertRowid);
  notifyIfNeeded(savedAlert, classified).catch(err =>
    console.error('[notifier] Error:', err.message)
  );

  return result.lastInsertRowid;
}

// ─── Notification helpers ──────────────────────────────────────────────────
async function sendResendEmail(incident, classified) {
  if (!resendClient) {
    console.log('[notifier] Resend not configured — skipping email.');
    return;
  }

  const priorityColor = classified.priority === 'High' ? '#c0392b' : '#e67e22';
  const confidencePct = Math.round(classified.confidence * 100);

  const { error } = await resendClient.emails.send({
    from: process.env.RESEND_FROM,
    to: process.env.RESEND_TO,
    subject: `[${classified.priority} Priority] ${classified.label} — ${classified.location}`,
    html: `
      <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
        <div style="background:${priorityColor};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0">
          <h2 style="margin:0;font-size:18px">Campus Security Alert</h2>
          <p style="margin:4px 0 0;font-size:14px;opacity:.85">${classified.priority} Priority · ${classified.severity} Severity</p>
        </div>
        <div style="border:1px solid #ddd;border-top:none;padding:20px;border-radius:0 0 8px 8px">
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="padding:6px 0;color:#666;width:160px">Incident</td><td style="padding:6px 0;font-weight:600">${classified.label}</td></tr>
            <tr><td style="padding:6px 0;color:#666">Location</td><td style="padding:6px 0">${classified.location}</td></tr>
            <tr><td style="padding:6px 0;color:#666">Time</td><td style="padding:6px 0">${new Date(classified.timestamp).toLocaleString()}</td></tr>
            <tr><td style="padding:6px 0;color:#666">Confidence</td><td style="padding:6px 0">${confidencePct}%</td></tr>
            <tr><td style="padding:6px 0;color:#666">Urgency Score</td><td style="padding:6px 0">${classified.urgencyScore} / 100</td></tr>
          </table>
          <div style="margin-top:16px;padding:12px 16px;background:#f8f8f8;border-radius:6px;font-size:14px;line-height:1.6">
            ${classified.summary}
          </div>
          <p style="margin-top:16px;font-size:12px;color:#999">Incident UUID: ${classified.uuid} · Source: ${incident.source}</p>
        </div>
      </div>
    `,
  });

  if (error) throw new Error(error.message);
  console.log(`[notifier] Email sent for ${classified.uuid}`);
}

async function makeTwilioCall(classified) {
  if (!twilioClient || !process.env.NOTIFY_PHONE || !process.env.TWILIO_FROM_NUMBER) {
    console.log('[notifier] Twilio not configured — skipping call.');
    return;
  }

  const confidencePct = Math.round(classified.confidence * 100);
  const message =
    `Campus security alert. High priority incident detected. ` +
    `${classified.label} at ${classified.location}. ` +
    `Confidence ${confidencePct} percent. ` +
    `Please check the security dashboard immediately.`;

  await twilioClient.calls.create({
    to: process.env.NOTIFY_PHONE,
    from: process.env.TWILIO_FROM_NUMBER,
    twiml: `<Response><Say voice="alice">${escapeXml(message)}</Say><Pause length="1"/></Response>`,
  });

  console.log(`[notifier] Call initiated for ${classified.uuid}`);
}

async function notifyIfNeeded(incident, classified) {
  if (notifiedUuids.has(classified.uuid)) return;
  notifiedUuids.add(classified.uuid);

  if (classified.priority === 'High') {
    const results = await Promise.allSettled([
      sendResendEmail(incident, classified),
      makeTwilioCall(classified),
    ]);
    results.forEach(r => {
      if (r.status === 'rejected') {
        console.error('[notifier] Error:', r.reason?.message || r.reason);
      }
    });
    return;
  }

  if (classified.priority === 'Medium') {
    try {
      await sendResendEmail(incident, classified);
    } catch (err) {
      console.error('[notifier] Email error:', err.message);
    }
  }
}

function safeParse(json, fallback) {
  try { return JSON.parse(json); } catch (_) { return fallback; }
}

// ─── Helper to build incident object for /incidents API response ───────────
function alertRowToIncident(row) {
  const metadata = safeParse(row.metadata_json, {});
  const timeline = safeParse(row.timeline_json, []);

  return {
    id: row.incident_uuid || String(row.id),
    label: buildLabel(row.description, 'Campus incident alert'),
    timestamp: row.timestamp,
    location: row.camera_id,
    confidence: metadata.scoring ? clamp((metadata.scoring.confidenceWeight || 0) / CONFIDENCE_SCALE, 0, 1) : 0.75,
    severity: row.severity,
    priority: row.priority || 'Low',
    recommendedAction: row.recommended_action || 'Log',
    status: row.incident_status || 'New',
    summary: metadata.summary || buildSummary({
      label: buildLabel(row.description, 'Campus incident'),
      location: row.camera_id,
      confidence: 0.75,
      priority: row.priority || 'Low',
      repeatedLocationCount: 0,
      crossCamera: false,
    }),
    notes: row.operator_notes || '',
    source: row.source || 'server',
    sourceKey: `${row.camera_id}-${row.timestamp}`,
    urgencyScore: row.urgency_score || 0,
    metadata,
    timeline,
  };
}

function isRestrictedZone(cameraId) {
  return !!db.prepare('SELECT 1 FROM restricted_zones WHERE camera_id = ?').get(cameraId);
}

function getMovementTimeline(personId) {
  return db.prepare(`
    SELECT camera_id, timestamp, incident, severity
    FROM sightings WHERE person_id = ?
    ORDER BY timestamp DESC LIMIT 20
  `).all(personId);
}

// ─── IP camera frame capture ───────────────────────────────────────────────
app.post('/capture-ip-camera', async (req, res) => {
  const { streamUrl } = req.body;
  const outputPath = path.join(__dirname, `tmp-${Date.now()}.jpg`);
  try {
    await new Promise((resolve, reject) => {
      ffmpeg(streamUrl).frames(1).output(outputPath)
        .on('end', resolve).on('error', reject).run();
    });
    const imageData = fs.readFileSync(outputPath).toString('base64');
    fs.unlinkSync(outputPath);
    res.json({ image: imageData });
  } catch (err) {
    res.status(500).json({ error: 'Camera capture failed.' });
  }
});

// ─── Emergency camera analysis ─────────────────────────────────────────────
app.post('/analyze-emergency', async (req, res) => {
  try {
    const { images } = req.body;
    if (!Array.isArray(images) || images.length !== 3) {
      return res.status(400).json({ error: 'Exactly 3 base64 images are required' });
    }

    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash-lite' });

    const parts = [
      { text: 'You are a campus safety AI. Analyze the following 3 sequential images captured during an emergency report. Identify any safety incidents, injuries, hazards, or situations requiring immediate attention. Classify severity as LOW, MEDIUM, or HIGH. Respond ONLY with raw JSON, no markdown:\n{"incident": true or false, "severity": "LOW, MEDIUM, or HIGH", "description": "one sentence summary of what you observe"}' },
      ...images.map(img => ({
        inlineData: { mimeType: 'image/jpeg', data: img }
      }))
    ];

    const result = await model.generateContent(parts);
    const raw = result.response.text().replace(/```json|```/g, '').trim();
    const analysis = JSON.parse(raw);

    const now = new Date().toISOString();
    const snapshotBase64 = req.body.snapshotBase64 || '';
    const userLocation = req.body.userLocation || null;
    const reporterName = typeof req.body.reporterName === 'string' ? req.body.reporterName : 'Guest';
    console.log(`[Emergency] snapshotBase64 length: ${snapshotBase64.length}`);

    const rowid = logAlert('EMERGENCY', 'INCIDENT', analysis.severity, analysis.description, [], 'EMERGENCY', {
      timestamp: now,
      confidence: analysis.severity === 'HIGH' ? 0.88 : analysis.severity === 'MEDIUM' ? 0.75 : 0.65,
      snapshotBase64,
      userLocation,
      reporterName,
    });

    const savedRow = db.prepare('SELECT incident_uuid FROM alerts WHERE id = ?').get(rowid);
    const incidentId = savedRow ? savedRow.incident_uuid : null;

    res.json({
      id: incidentId,
      severity: analysis.severity,
      description: analysis.description,
      incident: analysis.incident,
      timestamp: now,
    });
  } catch (err) {
    console.error('[Emergency Analysis Error]', err.message);
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

// ─── Chatbot ───────────────────────────────────────────────────────────────
app.post('/chat', async (req, res) => {
  const { message } = req.body;

  if (!message || typeof message !== 'string' || message.trim() === '') {
    return res.status(400).json({ error: 'Message is required' });
  }

  const sanitizedMessage = message.trim().slice(0, 2000);

  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash-lite' });

    const systemPrompt = 'You are a public safety assistant for a university campus. Analyze the situation described and provide clear guidance. Classify severity as LOW, MEDIUM, or HIGH. Always respond in English.';

    const chat = model.startChat({
      history: [
        { role: 'user', parts: [{ text: systemPrompt }] },
        { role: 'model', parts: [{ text: 'Understood. I am ready to assist with campus safety guidance.' }] }
      ]
    });

    const result = await chat.sendMessage(sanitizedMessage);
    const responseText = result.response.text();

    const severityMatch = responseText.match(/\b(HIGH|MEDIUM|LOW)\b/);
    const severity = severityMatch ? severityMatch[1] : 'MEDIUM';

    logAlert('CHATBOT', 'INCIDENT', severity, sanitizedMessage, [], 'CHATBOT', {
      confidence: severity === 'HIGH' ? 0.85 : 0.72,
    });

    res.json({ reply: responseText, severity });
  } catch (err) {
    console.error('[Chat Error]', err.message);
    res.status(500).json({ error: 'Failed to get response from AI' });
  }
});

// ─── Webhook receiver (merged1 format) ────────────────────────────────────
app.post('/incident', (req, res) => {
  const body = req.body;

  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const cameraId = typeof body.camera_id === 'string' ? body.camera_id : 'UNKNOWN';
  const alertType = typeof body.alert_type === 'string' ? body.alert_type : 'INCIDENT';
  const severity = typeof body.severity === 'string' ? body.severity : 'MEDIUM';
  const description = typeof body.description === 'string' ? body.description : '';
  const timestamp = typeof body.timestamp === 'string' ? body.timestamp : new Date().toISOString();

  logAlert(cameraId, alertType, severity, description, [], 'WEBHOOK', {
    timestamp,
    people: ensureArray(body.people),
    crossCamera: Boolean(body.cross_camera),
    crossCameraNote: body.cross_camera_note || '',
    snapshotBase64: body.snapshot_base64 || '',
    confidence: body.confidence ?? (severity === 'HIGH' ? 0.87 : 0.75),
  });

  res.status(200).json({ status: 'received' });
});

// ─── CS webhook receiver (CJ format) ──────────────────────────────────────
app.post('/webhooks/camera-incidents', (req, res) => {
  const payload = req.body || {};

  if (payload.alert_type && payload.alert_type !== 'INCIDENT') {
    return res.status(400).json({ message: 'Only INCIDENT alerts are supported.' });
  }

  const cameraId = payload.camera_id || 'Unknown Camera';
  const description = payload.description || '';
  const severity = payload.severity || 'MEDIUM';
  const timestamp = payload.timestamp || new Date().toISOString();
  const people = ensureArray(payload.people);
  const crossCamera = Boolean(payload.cross_camera);
  const crossCameraNote = payload.cross_camera_note || '';
  const snapshotBase64 = payload.snapshot_base64 || '';
  const confidence = payload.confidence ?? (crossCamera ? 0.91 : titleCaseSeverity(severity) === 'High' ? 0.87 : 0.78);

  const existing = db.prepare(
    `SELECT * FROM alerts WHERE camera_id = ? AND timestamp = ? AND description = ? AND source = 'camera-webhook' LIMIT 1`
  ).get(cameraId, timestamp, description);

  if (existing) {
    return res.status(200).json(alertRowToIncident(existing));
  }

  const id = logAlert(cameraId, 'INCIDENT', severity, description, [], 'camera-webhook', {
    timestamp,
    confidence,
    people,
    crossCamera,
    crossCameraNote,
    snapshotBase64,
  });

  const created = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);
  res.status(201).json(alertRowToIncident(created));
});

// ─── CS incidents API (reads from SQLite) ─────────────────────────────────
app.get('/incidents', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  const rows = db.prepare('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 150').all();

  const incidents = rows.map(alertRowToIncident);

  const sortedIncidents = incidents.sort((left, right) => {
    if (PRIORITIES[right.priority] !== PRIORITIES[left.priority]) {
      return PRIORITIES[right.priority] - PRIORITIES[left.priority];
    }
    if (right.urgencyScore !== left.urgencyScore) {
      return right.urgencyScore - left.urgencyScore;
    }
    if (SEVERITIES[right.severity] !== SEVERITIES[left.severity]) {
      return SEVERITIES[right.severity] - SEVERITIES[left.severity];
    }
    return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
  });

  res.json(sortedIncidents);
});

// ─── Update incident status ────────────────────────────────────────────────
app.patch('/incidents/:id/status', (req, res) => {
  const { id } = req.params;
  const status = req.body?.status;

  if (!STATUSES.includes(status)) {
    return res.status(400).json({ message: 'Invalid incident status.' });
  }

  const row = db.prepare('SELECT * FROM alerts WHERE incident_uuid = ?').get(id);
  if (!row) {
    return res.status(404).json({ message: 'Incident not found.' });
  }

  const timeline = safeParse(row.timeline_json, []);

  timeline.unshift(createTimelineEntry('status', `Status changed to ${status}.`, new Date().toISOString()));

  db.prepare('UPDATE alerts SET incident_status = ?, timeline_json = ? WHERE incident_uuid = ?').run(
    status,
    JSON.stringify(timeline),
    id
  );

  const updated = db.prepare('SELECT * FROM alerts WHERE incident_uuid = ?').get(id);
  res.json(alertRowToIncident(updated));
});

// ─── Update incident notes ─────────────────────────────────────────────────
app.patch('/incidents/:id/notes', (req, res) => {
  const { id } = req.params;
  const notes = typeof req.body?.notes === 'string' ? req.body.notes.trim() : '';

  const row = db.prepare('SELECT * FROM alerts WHERE incident_uuid = ?').get(id);
  if (!row) {
    return res.status(404).json({ message: 'Incident not found.' });
  }

  const timeline = safeParse(row.timeline_json, []);

  timeline.unshift(createTimelineEntry(
    'note',
    notes ? 'Operator note saved.' : 'Operator note cleared.',
    new Date().toISOString()
  ));

  db.prepare('UPDATE alerts SET operator_notes = ?, timeline_json = ? WHERE incident_uuid = ?').run(
    notes,
    JSON.stringify(timeline),
    id
  );

  const updated = db.prepare('SELECT * FROM alerts WHERE incident_uuid = ?').get(id);
  res.json(alertRowToIncident(updated));
});

// ─── Status ────────────────────────────────────────────────────────────────
app.get('/status', (req, res) => {
  const restricted = db.prepare('SELECT camera_id FROM restricted_zones').all().map(r => r.camera_id);
  res.json(Object.entries(cameraFeeds).map(([id, feed]) => ({
    cameraId: id,
    frameCount: feed.frames.length,
    lastIncident: feed.lastIncident || null,
    restricted: restricted.includes(id),
  })));
});

// ─── Restricted zones ──────────────────────────────────────────────────────
app.get('/restricted-zones', (req, res) => {
  res.json(db.prepare('SELECT camera_id FROM restricted_zones').all().map(r => r.camera_id));
});

app.post('/restricted-zones/:cameraId', (req, res) => {
  const { cameraId } = req.params;
  const existing = db.prepare('SELECT 1 FROM restricted_zones WHERE camera_id = ?').get(cameraId);
  if (existing) {
    db.prepare('DELETE FROM restricted_zones WHERE camera_id = ?').run(cameraId);
    res.json({ restricted: false });
  } else {
    db.prepare('INSERT INTO restricted_zones (camera_id) VALUES (?)').run(cameraId);
    res.json({ restricted: true });
  }
});

// ─── Archive incident ─────────────────────────────────────────────────────
app.post('/incidents/:id/archive', (req, res) => {
  const { id } = req.params;
  const reason = req.body?.reason;

  if (reason !== 'closed' && reason !== 'false_positive') {
    return res.status(400).json({ message: 'reason must be "closed" or "false_positive".' });
  }

  const row = db.prepare('SELECT * FROM alerts WHERE incident_uuid = ?').get(id);
  if (!row) {
    return res.status(404).json({ message: 'Incident not found.' });
  }

  const incident = alertRowToIncident(row);
  const archivedAt = new Date().toISOString();

  db.prepare(`
    INSERT OR REPLACE INTO archived_incidents (
      id, original_id, label, timestamp, location, confidence, severity, priority,
      recommended_action, incident_status, operator_notes, source, source_key,
      urgency_score, metadata, timeline, archived_at, archive_reason
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(),
    incident.id,
    incident.label,
    incident.timestamp,
    incident.location,
    incident.confidence,
    incident.severity,
    incident.priority,
    incident.recommendedAction,
    incident.status,
    incident.notes,
    incident.source,
    incident.sourceKey,
    incident.urgencyScore,
    JSON.stringify(incident.metadata),
    JSON.stringify(incident.timeline),
    archivedAt,
    reason
  );

  db.prepare('DELETE FROM alerts WHERE incident_uuid = ?').run(id);

  res.json({ success: true, archived_at: archivedAt, archive_reason: reason });
});

// ─── Archived incidents ────────────────────────────────────────────────────
app.get('/archived-incidents', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const rows = db.prepare('SELECT * FROM archived_incidents ORDER BY archived_at DESC').all();
  const incidents = rows.map((row) => {
    const metadata = safeParse(row.metadata, {});
    const timeline = safeParse(row.timeline, []);
    return {
      id: row.id,
      originalId: row.original_id,
      label: row.label,
      timestamp: row.timestamp,
      location: row.location,
      confidence: row.confidence,
      severity: row.severity,
      priority: row.priority,
      recommendedAction: row.recommended_action,
      status: row.incident_status,
      notes: row.operator_notes,
      source: row.source,
      sourceKey: row.source_key,
      urgencyScore: row.urgency_score,
      metadata,
      timeline,
      archivedAt: row.archived_at,
      archiveReason: row.archive_reason,
    };
  });
  res.json(incidents);
});

// ─── Alerts (raw log) ──────────────────────────────────────────────────────
app.get('/alerts', (req, res) => {
  res.json(db.prepare('SELECT * FROM alerts ORDER BY timestamp DESC').all());
});

// ─── People ────────────────────────────────────────────────────────────────
app.get('/people', (req, res) => {
  res.json(db.prepare('SELECT * FROM people ORDER BY last_seen DESC').all());
});

app.get('/people/:id/sightings', (req, res) => {
  res.json(db.prepare(
    'SELECT * FROM sightings WHERE person_id = ? ORDER BY timestamp DESC'
  ).all(req.params.id));
});

app.get('/people/:id/timeline', (req, res) => {
  res.json(getMovementTimeline(req.params.id));
});

app.post('/people/:id/notes', (req, res) => {
  db.prepare('UPDATE people SET notes = ? WHERE id = ?').run(req.body.notes, req.params.id);
  res.json({ success: true });
});

app.post('/people/:id/flag', (req, res) => {
  const person = db.prepare('SELECT flagged FROM people WHERE id = ?').get(req.params.id);
  if (!person) return res.status(404).json({ error: 'Not found' });
  const newFlag = person.flagged ? 0 : 1;
  db.prepare('UPDATE people SET flagged = ? WHERE id = ?').run(newFlag, req.params.id);
  res.json({ success: true, flagged: !!newFlag });
});

app.delete('/people/:id', (req, res) => {
  db.prepare('DELETE FROM sightings WHERE person_id = ?').run(req.params.id);
  db.prepare('DELETE FROM people WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── Static files ──────────────────────────────────────────────────────────
// Dashboard React app (must come before generic static to avoid conflicts)
const dashboardDir = path.join(__dirname, 'public', 'dashboard');
app.use('/dashboard', express.static(dashboardDir));
app.get('/dashboard/*path', (req, res) => {
  const indexPath = path.join(dashboardDir, 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      res.status(500).json({ message: 'Dashboard build not found. Run: npm run build:client' });
    }
  });
});

// Main app (chatbot + emergency button)
app.use(express.static(path.join(__dirname, 'public')));

// ─── Error handler (Express 5 compatible) ─────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ message: 'Unexpected server error.' });
});

// ─── Start ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
