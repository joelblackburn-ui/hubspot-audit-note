const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Security: Helmet headers
app.use(helmet());

// Security: Rate limiting (600 req/min)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' }
});
app.use(limiter);

// Parse JSON bodies
app.use(express.json());

// Joi validation schema
const requestSchema = Joi.object({
  contactId: Joi.string().required(),
  primaryCompany: Joi.object({
    id: Joi.string().required(),
    name: Joi.string().required(),
    domain: Joi.string().allow('', null)
  }).required(),
  removedCompanies: Joi.array().items(
    Joi.object({
      id: Joi.string().required(),
      name: Joi.string().required(),
      domain: Joi.string().allow('', null)
    })
  ).min(1).required()
});

// Constant-time comparison for API key authentication
function secureCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still do a comparison to maintain constant time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// API key authentication middleware
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const expectedKey = process.env.API_KEY;

  if (!expectedKey) {
    console.error('API_KEY environment variable not configured');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  if (!secureCompare(apiKey, expectedKey)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

// Format note body
function formatNoteBody(primaryCompany, removedCompanies, timestamp) {
  const hubspotBaseUrl = 'https://app.hubspot.com/contacts/145521027/record/0-2';

  let body = '=== COMPANY ASSOCIATION AUDIT ===\n\n';

  // Primary company section
  body += 'PRIMARY COMPANY (Retained)\n';
  body += '─────────────────────────────\n';
  body += `Name: ${primaryCompany.name}\n`;
  body += `Domain: ${primaryCompany.domain || 'N/A'}\n`;
  body += `HubSpot: ${hubspotBaseUrl}/${primaryCompany.id}\n\n`;

  // Removed associations section
  body += 'REMOVED ASSOCIATIONS\n';
  body += '─────────────────────────────\n';

  removedCompanies.forEach((company, index) => {
    body += `\n${index + 1}. ${company.name}\n`;
    body += `   Domain: ${company.domain || 'N/A'}\n`;
    body += `   HubSpot: ${hubspotBaseUrl}/${company.id}\n`;
  });

  body += '\n─────────────────────────────\n';
  body += `Timestamp: ${timestamp}`;

  return body;
}

// HubSpot API: Get current contact property value
async function getContactProperty(contactId, property) {
  const hubspotKey = process.env.HUBSPOT_API_KEY;

  const response = await fetch(
    `https://api.hubapi.com/crm/v3/objects/contacts/${contactId}?properties=${property}`,
    {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${hubspotKey}`,
        'Content-Type': 'application/json'
      }
    }
  );

  if (!response.ok) {
    if (response.status === 404) {
      return null;
    }
    throw new Error(`HubSpot API error: ${response.status}`);
  }

  const data = await response.json();
  return data.properties?.[property] || '';
}

// HubSpot API: Update contact property
async function updateContactProperty(contactId, property, value) {
  const hubspotKey = process.env.HUBSPOT_API_KEY;

  const response = await fetch(
    `https://api.hubapi.com/crm/v3/objects/contacts/${contactId}`,
    {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${hubspotKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        properties: {
          [property]: value
        }
      })
    }
  );

  if (!response.ok) {
    throw new Error(`HubSpot API error: ${response.status}`);
  }

  return response.json();
}

// HubSpot API: Create note
async function createNote(contactId, noteBody) {
  const hubspotKey = process.env.HUBSPOT_API_KEY;

  // Create the note
  const createResponse = await fetch(
    'https://api.hubapi.com/crm/v3/objects/notes',
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${hubspotKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        properties: {
          hs_note_body: noteBody,
          hs_timestamp: new Date().toISOString()
        }
      })
    }
  );

  if (!createResponse.ok) {
    throw new Error(`HubSpot API error creating note: ${createResponse.status}`);
  }

  const noteData = await createResponse.json();
  const noteId = noteData.id;

  // Associate note with contact
  const associateResponse = await fetch(
    `https://api.hubapi.com/crm/v3/objects/notes/${noteId}/associations/contacts/${contactId}/note_to_contact`,
    {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${hubspotKey}`,
        'Content-Type': 'application/json'
      }
    }
  );

  if (!associateResponse.ok) {
    throw new Error(`HubSpot API error associating note: ${associateResponse.status}`);
  }

  return noteData;
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Main endpoint: Create audit note
app.post('/audit-note', authenticateApiKey, async (req, res) => {
  try {
    // Validate input
    const { error, value } = requestSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { contactId, primaryCompany, removedCompanies } = value;

    // Check HubSpot API key is configured
    if (!process.env.HUBSPOT_API_KEY) {
      console.error('HUBSPOT_API_KEY environment variable not configured');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const timestamp = new Date().toISOString();

    // Get current removed_company_ids value
    let currentIds = await getContactProperty(contactId, 'removed_company_ids');

    // Append new IDs (comma-separated)
    const newIds = removedCompanies.map(c => c.id);
    let updatedIds;

    if (currentIds && currentIds.trim()) {
      // Parse existing IDs and add new ones (avoiding duplicates)
      const existingSet = new Set(currentIds.split(',').map(id => id.trim()).filter(Boolean));
      newIds.forEach(id => existingSet.add(id));
      updatedIds = Array.from(existingSet).join(',');
    } else {
      updatedIds = newIds.join(',');
    }

    // Update the contact property
    await updateContactProperty(contactId, 'removed_company_ids', updatedIds);

    // Create the audit note
    const noteBody = formatNoteBody(primaryCompany, removedCompanies, timestamp);
    const note = await createNote(contactId, noteBody);

    res.json({
      success: true,
      noteId: note.id,
      contactId,
      removedCompanyIds: updatedIds,
      timestamp
    });

  } catch (err) {
    console.error('Error processing audit note:', err.message);
    res.status(500).json({ error: 'Failed to process audit note' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler - never expose stack traces
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`hubspot-audit-note service running on port ${PORT}`);
});
