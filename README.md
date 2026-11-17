# TalentMind AI

**Assignment:** talentmindAI
**Author:** Dinakar . K

## 1. Problem Statement
Recruitment teams need an efficient way to manage candidates, job requisitions, resumes, and candidate reviews. Manual screening makes consistent candidate evaluation difficult.

## 2. Solution Approach
TalentMind AI provides a web application for:
- User registration and authentication
- Candidate management
- Job requisition management
- PDF and TXT resume upload and text extraction
- Candidate-to-job skill matching
- Candidate reviews and audit logging
- Knowledge-base document storage and text search
- Webhook registration
- LangGraph workflow orchestration

Candidate matching currently uses deterministic, rule-based scoring. It does not make automated hiring decisions.

## 3. Technologies and Dependencies

### Frontend
- Next.js
- React
- TypeScript
- Tailwind CSS
- Material UI

### Backend
- Python
- FastAPI
- Uvicorn
- LangGraph
- LangChain Core
- SQLite
- PyMuPDF

### Security
- PyJWT
- RS256
- Argon2
- HMAC-SHA256

### Deployment
- AWS EC2
- Ubuntu
- Nginx
- PM2
- systemd

## 4. Setup Instructions

### Prerequisites
- Node.js and npm
- Python 3.12
- Git
- pip

### Frontend Installation
    npm install

### Backend Installation
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Configure required backend environment variables and RSA key files before starting the backend. Never commit secrets or private keys.

## 5. Execution Steps

### Start Backend
    cd backend
    source venv/bin/activate
    uvicorn app.main:app --host 127.0.0.1 --port 8000

### Start Frontend in another terminal
    npm run dev

Frontend: http://localhost:3000

Backend API documentation: http://127.0.0.1:8000/docs

Backend health check: http://127.0.0.1:8000/health

## 6. Application Workflow
1. Register or sign in.
2. Manage candidate information.
3. Create job requisitions.
4. Upload candidate resumes.
5. Run the candidate matching workflow.
6. Review matching results.
7. Record candidate reviews and view audit information.

## 7. Deployment
The application uses AWS EC2, Nginx, Next.js with PM2, FastAPI with systemd, and SQLite.

See [DEPLOYMENT.md](DEPLOYMENT.md).

## 8. API Documentation
See [API.md](API.md). FastAPI also provides interactive documentation at `/docs`.

## 9. Current Implementation Notes
- Matching uses deterministic rules and recognized skills.
- Resume extraction supports PDF and TXT.
- Knowledge-base search uses basic SQLite text matching.
- Evaluation currently performs a baseline database check.
- Vector search and external LLM integrations are not configured.

## 10. Assignment Submission Details
**Project:** TalentMind AI
**Assignment:** talentmindAI
**Author:** Dinakar . K

**Personal GitHub Repository:**
https://github.com/manodinakar007-spec/TalentmindAI
