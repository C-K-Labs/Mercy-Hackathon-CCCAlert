# Mercy-Hackathon-CCCAlert
AI-powered campus safety system built at Mercy University AI Hackathon. Real-time incident reporting via chatbot and emergency camera analysis, with automated priority classification and security dashboard.
> This is a prototype built under hackathon conditions. 
> Authentication, authorization, and rate limiting are 
> not implemented and should be added before any 
> production use.

# CCCAlert

AI-powered campus safety system built at the Mercy University AI Hackathon, April 2026.
Theme: Public Safety and Emergency Support.

## Problem

Campus safety systems rely on phone calls. When someone is in danger and cannot speak or type, there is no fast way to report what is happening and response time suffers.

## Solution

CCCAlert gives anyone on campus two ways to report a safety incident instantly, feeding into a unified dashboard for security officers.

## Features

### Sign In
Users sign in with their name and phone number so security knows who submitted the report. Guest access is available for situations where there is no time to fill in any information.

### Chatbot
Describe the situation in natural language. Google Gemini responds as a campus public safety assistant, classifies severity as LOW, MEDIUM, or HIGH, and provides immediate guidance. The report is automatically saved and sent to the security dashboard.

### Emergency Button
For situations where typing is impossible. One button press activates the front camera and captures three screenshots at 3, 5, and 10 seconds. All three images are analyzed by Gemini in a single API call. The result is saved with the captured photo as evidence and a dispatch status tracker updates on the user's screen in real time. The camera can be flipped to rear to capture the scene ahead.

### Security Dashboard
Real-time incident monitoring for campus security officers. Emergency incidents are visually highlighted. Each incident includes a priority score, recommended action, evidence photo, and full audit trail. High priority incidents automatically trigger a phone call and email alert to the security team. Officers can escalate, review, dismiss, or close incidents. Closed and dismissed incidents are archived with full filter controls.

## AI

- Google Gemini (gemini-2.5-flash-lite) for chatbot guidance, emergency image analysis, and severity classification
- Rule-based urgency scoring for priority classification (Low, Moderate, High, Critical)
- Automated alerts via Twilio (phone) and Resend (email) for high priority incidents

## Tech Stack

- Backend: Node.js, Express 5
- Frontend: HTML, CSS, Vanilla JavaScript
- Dashboard: React, Vite, Tailwind CSS
- Database: SQLite
- AI: Google Gemini API
- Notifications: Twilio, Resend

## Setup

```bash
# Install dependencies and build dashboard
npm run setup

# Copy and fill in environment variables
cp .env.example .env

# Start the server
npm start
```

Main app: `http://localhost:4000`
Security dashboard: `http://localhost:4000/dashboard`

## Environment Variables

GEMINI_API_KEY=
PORT=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=
NOTIFY_PHONE=
RESEND_API_KEY=
RESEND_FROM=
RESEND_TO=

## Team

Team CCCA. Mercy University AI Hackathon, April 18-19, 2026.
