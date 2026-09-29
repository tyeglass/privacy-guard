# 🔒 PrivacyGuard — Privacy Violation Detector for Web Applications

> A production-grade privacy compliance and security analysis platform. Scans websites for GDPR, CCPA, and COPPA violations, data exposure risks, third-party trackers, and insecure data handling.

![Dashboard Preview](docs/screenshots/dashboard.png)

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **URL Scanner** | Crawls public pages and performs deep privacy analysis |
| **Cookie Analysis** | Detects Secure/HttpOnly flags, consent banners, third-party cookies |
| **Form Analysis** | Identifies excessive data collection, HTTP submissions, missing disclosures |
| **HTTPS / SSL Check** | Verifies encryption, certificate validity, and expiry |
| **Tracker Detection** | Detects GA4, GTM, Meta Pixel, TikTok Pixel, Hotjar, Mixpanel, Adobe Analytics |
| **Privacy Policy Detection** | Checks for Privacy Policy, Cookie Policy, Terms of Service |
| **Data Exposure Scan** | Finds hardcoded API keys, AWS keys, emails, phone numbers |
| **Compliance Assessment** | GDPR / CCPA / COPPA scoring (0–100) with per-regulation breakdown |
| **Risk Scoring** | Critical / High / Medium / Low / Informational severity levels |
| **Report Generation** | Downloadable PDF and JSON reports with findings and recommendations |
| **Dashboard** | Overview cards, pie/bar charts, risk distribution graphs |
| **Scan History** | Historical compliance score trends per site |
| **JWT Authentication** | Register, login, protected scan history |
| **Admin Panel** | Manage users, scans, and reports |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   React Frontend                     │
│   TypeScript · Tailwind CSS · Chart.js · Vite       │
└──────────────────────┬──────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────▼──────────────────────────────┐
│              Spring Boot API (Java 21)               │
│   REST Controllers · JWT Security · Rate Limiting    │
│                                                      │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────┐  │
│  │ ScanService  │  │RiskScoring │  │ReportService│  │
│  └──────┬───────┘  └─────┬──────┘  └──────┬──────┘  │
│         │                │                │          │
│  ┌──────▼───────────────────────────────────────┐   │
│  │            Scanning Engine                   │   │
│  │  HTTPS · Cookies · Forms · Trackers          │   │
│  │  Policy · Data Exposure · Compliance          │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────┘
                       │ JPA / Flyway
┌──────────────────────▼──────────────────────────────┐
│                   PostgreSQL 16                      │
│   scans · findings · users · rate_limits             │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Docker)

### Prerequisites
- Docker Engine ≥ 24
- Docker Compose v2

```bash
# 1. Clone the repository
git clone https://github.com/yourname/privacy-guard.git
cd privacy-guard

# 2. Copy environment template
cp .env.example .env
# Edit .env: set DB_PASSWORD and JWT_SECRET

# 3. Build and launch all services
docker compose up --build

# 4. Open the app
open http://localhost:3000
```

Services:
| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| API | http://localhost:8080 |
| Swagger UI | http://localhost:8080/swagger-ui.html |
| Actuator | http://localhost:8080/actuator/health |

---

## 🛠️ Local Development

### Backend (Spring Boot)

```bash
cd backend

# Start PostgreSQL only
docker compose up postgres -d

# Run Spring Boot with dev profile
./mvnw spring-boot:run -Dspring-boot.run.profiles=local

# Run tests
./mvnw test
```

### Frontend (React)

```bash
cd frontend

npm install
npm start        # http://localhost:3000
npm test         # Jest + React Testing Library
npm run build    # Production build
```

---

## 🔌 API Reference

### Initiate Scan
```http
POST /api/scan
Content-Type: application/json

{ "url": "https://example.com" }
```
```json
{ "scanId": 42, "url": "https://example.com", "status": "PENDING" }
```

### Poll Status
```http
GET /api/results/{scanId}/status
```
```json
{ "scanId": 42, "status": "IN_PROGRESS" }
```

### Get Full Results
```http
GET /api/results/{scanId}
```
```json
{
  "id": 42,
  "url": "https://example.com",
  "overallScore": 74,
  "gdprScore": 68,
  "ccpaScore": 79,
  "coppaScore": 88,
  "findings": [
    {
      "severity": "HIGH",
      "category": "COOKIES",
      "title": "Missing Cookie Consent Banner",
      "description": "...",
      "recommendation": "..."
    }
  ]
}
```

### Download Report
```http
GET /api/report/{scanId}?format=pdf
GET /api/report/{scanId}?format=json
```

### Authentication
```http
POST /api/auth/register
POST /api/auth/login
```

---

## 🗄️ Database Schema

```sql
scans     (id, url, scan_date, overall_score, gdpr_score, ccpa_score,
           coppa_score, https_enabled, ssl_valid, status, user_id)

findings  (id, scan_id, category, severity, title, description,
           recommendation, evidence)

users     (id, email, password, full_name, role, enabled, created_at)
```

---

## 🔒 Security

- **Input validation**: URL sanitization, private/localhost IP blocking
- **Rate limiting**: 20 scans/hour per IP (configurable)
- **JWT Authentication**: RS256-signed tokens, 24h expiry
- **OWASP compliance**: CORS, CSRF protection, secure headers
- **No credentials stored**: Passwords hashed with BCrypt (strength 12)

---

## 📊 Risk Scoring

| Severity | Score Penalty | Examples |
|----------|-------------|---------|
| Critical | −25 pts | API key exposed, HTTP form submission, no HTTPS |
| High | −15 pts | Missing cookie consent, missing privacy policy, trackers before consent |
| Medium | −8 pts | Missing HttpOnly/Secure flags, missing cookie policy |
| Low | −3 pts | Missing ToS, policy hard to find |
| Informational | 0 pts | Valid SSL, HTTPS confirmed |

Compliance scores are calculated separately for GDPR, CCPA, and COPPA by weighting findings relevant to each regulation.

---

## 🛣️ Roadmap

- [ ] Scheduled recurring scans (daily/weekly/monthly)
- [ ] Email notifications on score change
- [ ] Browser extension for real-time scanning
- [ ] Multi-page deep crawl (Selenium/Playwright)
- [ ] Webhook integrations (Slack, PagerDuty)
- [ ] SOC 2 / ISO 27001 compliance checks
- [ ] Bulk URL scanning via CSV upload

---

## 🧪 Testing

```bash
# Backend unit + integration tests
./mvnw test -pl backend

# Backend with TestContainers (real PostgreSQL)
./mvnw verify -pl backend

# Frontend
cd frontend && npm test
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

Built as a portfolio project demonstrating full-stack Java/React development, security engineering, and privacy compliance expertise.
