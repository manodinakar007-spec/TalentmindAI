import os
import ipaddress
import secrets
import subprocess
import socket
import hashlib
import hmac
import httpx
import sqlite3
import uuid
import re
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, File, Form, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from app.agent_workflow import run_agent_workflow

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "talentmind.db"
JWT_PRIVATE_KEY_PATH = BASE_DIR / "keys" / "jwt_private.pem"
JWT_PUBLIC_KEY_PATH = BASE_DIR / "keys" / "jwt_public.pem"
JWT_ALGORITHM = "RS256"
TOKEN_MINUTES = 15

if not JWT_PRIVATE_KEY_PATH.is_file() or not JWT_PUBLIC_KEY_PATH.is_file():
    raise RuntimeError("RS256 key files are missing from backend/keys.")

JWT_PRIVATE_KEY = JWT_PRIVATE_KEY_PATH.read_text()
JWT_PUBLIC_KEY = JWT_PUBLIC_KEY_PATH.read_text()

app = FastAPI(
    title="TalentMind AI API",
    description="Talent intelligence platform API",
    version="1.0.0",
)

password_hash = PasswordHash.recommended()
bearer = HTTPBearer()


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'recruiter',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                skills TEXT NOT NULL DEFAULT '',
                experience_years REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS requisitions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                title TEXT NOT NULL,
                department TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
            ON refresh_tokens (family_id);

            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
            ON refresh_tokens (user_id);

            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                secret TEXT NOT NULL,
                events TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_webhooks_tenant
            ON webhooks (tenant_id, active);
        """)


@app.on_event("startup")
def startup():
    initialize_database()


def now():
    return datetime.now(timezone.utc).isoformat()


def audit(tenant_id, user_id, action):
    with get_db() as db:
        db.execute(
            "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), tenant_id, user_id, action, now()),
        )


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=256)


class CandidateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    email: EmailStr | None = None
    skills: list[str] = []
    experience_years: float = Field(default=0, ge=0, le=70)


class RequisitionCreate(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    department: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=10000)


def create_token(user):
    payload = {
        "sub": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm=JWT_ALGORITHM)


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_PUBLIC_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        return {
            "id": payload["sub"],
            "tenant_id": payload["tenant_id"],
            "role": payload["role"],
        }
    except (jwt.InvalidTokenError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health")
def health():
    return {"status": "healthy", "service": "talentmind-api"}


@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest):
    user_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())

    try:
        with get_db() as db:
            db.execute(
                """INSERT INTO users
                   (id, email, password_hash, tenant_id, role, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    data.email.lower(),
                    password_hash.hash(data.password),
                    tenant_id,
                    "admin",
                    now(),
                ),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email is already registered")

    return {"message": "Account created. You can now sign in."}


@app.post("/auth/token")
def login(data: LoginRequest):
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (data.email.lower(),),
        ).fetchone()

    if not user or not password_hash.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    refresh_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    family_id = str(uuid.uuid4())
    refresh_expiry = datetime.now(timezone.utc) + timedelta(days=30)

    with get_db() as db:
        db.execute(
            """INSERT INTO refresh_tokens
               (token_hash, family_id, user_id, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (token_hash, family_id, user["id"], refresh_expiry.isoformat(), now()),
        )

    return {
        "access_token": create_token(user),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": TOKEN_MINUTES * 60,
        "refresh_expires_in": 30 * 24 * 60 * 60,
    }


@app.post("/auth/refresh")
def refresh_access_token(data: RefreshRequest):
    token_hash = hashlib.sha256(data.refresh_token.encode()).hexdigest()
    invalid = False
    user = None
    new_refresh_token = None

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        record = db.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()

        if not record:
            invalid = True
        elif record["revoked_at"]:
            # Reuse of a rotated token revokes its entire token family.
            db.execute(
                """UPDATE refresh_tokens SET revoked_at = ?
                   WHERE family_id = ? AND revoked_at IS NULL""",
                (now(), record["family_id"]),
            )
            invalid = True
        elif record["expires_at"] <= now():
            db.execute(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ?",
                (now(), token_hash),
            )
            invalid = True
        else:
            user = db.execute(
                "SELECT * FROM users WHERE id = ?",
                (record["user_id"],),
            ).fetchone()

            if not user:
                invalid = True
            else:
                db.execute(
                    "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ?",
                    (now(), token_hash),
                )
                new_refresh_token = secrets.token_urlsafe(48)
                new_hash = hashlib.sha256(
                    new_refresh_token.encode()
                ).hexdigest()
                db.execute(
                    """INSERT INTO refresh_tokens
                       (token_hash, family_id, user_id, expires_at, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        new_hash,
                        record["family_id"],
                        user["id"],
                        (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                        now(),
                    ),
                )

    if invalid:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or reused refresh token",
        )

    return {
        "access_token": create_token(user),
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": TOKEN_MINUTES * 60,
        "refresh_expires_in": 30 * 24 * 60 * 60,
    }


@app.get("/auth/me")
def me(user=Depends(current_user)):
    with get_db() as db:
        record = db.execute(
            "SELECT id, email, role, tenant_id FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    if not record:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(record)


@app.post("/candidates", status_code=201)
def create_candidate(data: CandidateCreate, user=Depends(current_user)):
    candidate_id = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            """INSERT INTO candidates
               (id, tenant_id, name, email, skills, experience_years, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                candidate_id,
                user["tenant_id"],
                data.name,
                data.email,
                ", ".join(data.skills),
                data.experience_years,
                now(),
            ),
        )
    audit(user["tenant_id"], user["id"], "candidate.created")
    deliver_webhook_event(
        user["tenant_id"],
        "candidate.created",
        {
            "candidate_id": candidate_id,
            "name": data.name,
            "email": data.email,
            "skills": data.skills,
            "experience_years": data.experience_years,
        },
    )
    return {"id": candidate_id, **data.model_dump()}


@app.get("/candidates")
def list_candidates(user=Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, name, email, skills, experience_years, created_at
               FROM candidates WHERE tenant_id = ? ORDER BY created_at DESC""",
            (user["tenant_id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/requisitions", status_code=201)
def create_requisition(data: RequisitionCreate, user=Depends(current_user)):
    requisition_id = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            """INSERT INTO requisitions
               (id, tenant_id, title, department, description, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'open', ?)""",
            (
                requisition_id,
                user["tenant_id"],
                data.title,
                data.department,
                data.description,
                now(),
            ),
        )
    audit(user["tenant_id"], user["id"], "requisition.created")
    return {"id": requisition_id, **data.model_dump(), "status": "open"}


@app.get("/requisitions")
def list_requisitions(user=Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT id, title, department, description, status, created_at
               FROM requisitions WHERE tenant_id = ? ORDER BY created_at DESC""",
            (user["tenant_id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/audit")
def list_audit_logs(user=Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT action, created_at FROM audit_logs
               WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100""",
            (user["tenant_id"],),
        ).fetchall()
    return [dict(row) for row in rows]

# --- Pipeline, evaluation, and knowledge-base extensions ---

import json
import re


class PipelineRequest(BaseModel):
    requisition_id: str
    candidate_ids: list[str] = []


class KnowledgeDocument(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=50000)


class EvaluationRequest(BaseModel):
    name: str = Field(default="Baseline evaluation", max_length=200)


class ReviewCreate(BaseModel):
    decision: str = Field(min_length=1, max_length=30)
    comment: str = Field(default="", max_length=2000)


class WebhookCreate(BaseModel):
    target_url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(min_length=1, max_length=20)


@app.on_event("startup")
def initialize_extended_tables():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                requisition_id TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evaluation_runs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_documents (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)



@app.on_event("startup")
def initialize_review_table():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS candidate_reviews (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_candidate_reviews_tenant
            ON candidate_reviews (tenant_id, candidate_id, created_at)
        """)


@app.post("/candidates/{candidate_id}/reviews", status_code=201)
def create_candidate_review(
    candidate_id: str,
    data: ReviewCreate,
    user=Depends(current_user),
):
    allowed_decisions = {"shortlisted", "rejected", "needs_review"}
    if data.decision not in allowed_decisions:
        raise HTTPException(
            status_code=422,
            detail="Decision must be shortlisted, rejected, or needs_review",
        )

    if user["role"].lower() not in {
        "admin", "recruiter", "hiring_manager", "hiringmanager"
    }:
        raise HTTPException(
            status_code=403,
            detail="Your role cannot submit candidate reviews",
        )

    review_id = str(uuid.uuid4())
    created_at = now()

    with get_db() as db:
        candidate = db.execute(
            "SELECT id FROM candidates WHERE id = ? AND tenant_id = ?",
            (candidate_id, user["tenant_id"]),
        ).fetchone()

        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")

        db.execute(
            """INSERT INTO candidate_reviews
               (id, tenant_id, candidate_id, reviewer_id,
                decision, comment, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                review_id,
                user["tenant_id"],
                candidate_id,
                user["id"],
                data.decision,
                data.comment,
                created_at,
            ),
        )

    audit(
        user["tenant_id"],
        user["id"],
        "candidate.review." + data.decision,
    )
    deliver_webhook_event(
        user["tenant_id"],
        "candidate.review." + data.decision,
        {
            "review_id": review_id,
            "candidate_id": candidate_id,
            "decision": data.decision,
            "comment": data.comment,
            "reviewer_id": user["id"],
        },
    )

    return {
        "review_id": review_id,
        "candidate_id": candidate_id,
        "decision": data.decision,
        "comment": data.comment,
        "reviewer_id": user["id"],
        "created_at": created_at,
    }


@app.get("/candidates/{candidate_id}/reviews")
def list_candidate_reviews(
    candidate_id: str,
    user=Depends(current_user),
):
    with get_db() as db:
        candidate = db.execute(
            "SELECT id FROM candidates WHERE id = ? AND tenant_id = ?",
            (candidate_id, user["tenant_id"]),
        ).fetchone()

        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")

        rows = db.execute(
            """SELECT id, candidate_id, reviewer_id, decision,
                      comment, created_at
               FROM candidate_reviews
               WHERE candidate_id = ? AND tenant_id = ?
               ORDER BY created_at DESC""",
            (candidate_id, user["tenant_id"]),
        ).fetchall()

    return {
        "candidate_id": candidate_id,
        "count": len(rows),
        "reviews": [dict(row) for row in rows],
    }



@app.post("/webhooks", status_code=201)
def register_webhook(data: WebhookCreate, user=Depends(current_user)):
    allowed_roles = {"admin", "recruiter"}
    if user["role"].lower() not in allowed_roles:
        raise HTTPException(status_code=403, detail="Your role cannot register webhooks")

    parsed = urlsplit(data.target_url)
    hostname = parsed.hostname or ""

    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or hostname.lower() == "localhost"
        or hostname.lower().endswith(".local")
    ):
        raise HTTPException(status_code=422, detail="A valid public HTTPS URL is required")

    try:
        address = ipaddress.ip_address(hostname)
        if not address.is_global:
            raise HTTPException(status_code=422, detail="Webhook URL must not use a private IP")
    except ValueError:
        pass

    allowed_events = {
        "candidate.created",
        "candidate.deleted",
        "candidate.review.shortlisted",
        "candidate.review.rejected",
        "candidate.review.needs_review",
    }

    if not set(data.events).issubset(allowed_events):
        raise HTTPException(status_code=422, detail="One or more webhook events are unsupported")

    webhook_id = str(uuid.uuid4())
    secret = secrets.token_urlsafe(32)
    created_at = now()

    with get_db() as db:
        db.execute(
            """INSERT INTO webhooks
               (id, tenant_id, user_id, target_url, secret, events, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
            (
                webhook_id,
                user["tenant_id"],
                user["id"],
                data.target_url,
                secret,
                json.dumps(data.events),
                created_at,
            ),
        )

    audit(user["tenant_id"], user["id"], "webhook.created")

    return {
        "id": webhook_id,
        "target_url": data.target_url,
        "events": data.events,
        "secret": secret,
        "created_at": created_at,
        "note": "Save this signing secret securely. It will not be returned again.",
    }


def deliver_webhook_event(tenant_id: str, event: str, payload: dict):
    """Deliver tenant webhook events with HMAC-SHA256 signatures."""
    results = []

    with get_db() as db:
        hooks = db.execute(
            """SELECT id, target_url, secret, events
               FROM webhooks
               WHERE tenant_id = ? AND active = 1""",
            (tenant_id,),
        ).fetchall()

    for hook in hooks:
        if event not in json.loads(hook["events"]):
            continue

        try:
            parsed = urlsplit(hook["target_url"])
            hostname = parsed.hostname
            port = parsed.port or 443

            if (
                parsed.scheme != "https"
                or not hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise ValueError("Invalid HTTPS webhook URL")

            addresses = socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
            public_ips = sorted({
                item[4][0] for item in addresses
                if ipaddress.ip_address(item[4][0]).is_global
            })

            if not public_ips or len(public_ips) != len({
                item[4][0] for item in addresses
            }):
                raise ValueError("Webhook host has a non-public IP address")

            # Pin curl to the validated IP to prevent DNS rebinding.
            pinned_ip = public_ips[0]
            resolve_ip = (
                f"[{pinned_ip}]"
                if ":" in pinned_ip else pinned_ip
            )

            body = json.dumps({
                "id": str(uuid.uuid4()),
                "event": event,
                "created_at": now(),
                "data": payload,
            }, separators=(",", ":"), ensure_ascii=False)

            timestamp = str(int(datetime.now(timezone.utc).timestamp()))
            signed_content = timestamp + "." + body

            signature = hmac.new(
                hook["secret"].encode(),
                signed_content.encode(),
                hashlib.sha256,
            ).hexdigest()

            command = [
                "curl",
                "--silent",
                "--show-error",
                "--output", "/dev/null",
                "--write-out", "%{http_code}",
                "--request", "POST",
                "--header", "Content-Type: application/json",
                "--header", "X-TalentMind-Event: " + event,
                "--header", "X-TalentMind-Timestamp: " + timestamp,
                "--header", "X-TalentMind-Signature: sha256=" + signature,
                "--data-binary", "@-",
                "--connect-timeout", "5",
                "--max-time", "10",
                "--max-redirs", "0",
                "--proto", "=https",
                "--noproxy", "*",
                "--resolve", f"{hostname}:{port}:{resolve_ip}",
                hook["target_url"],
            ]

            response = subprocess.run(
                command,
                input=body,
                text=True,
                capture_output=True,
                timeout=12,
                check=False,
            )

            status_code = int(response.stdout.strip() or "0")
            results.append({
                "webhook_id": hook["id"],
                "delivered": 200 <= status_code < 300,
                "status_code": status_code,
            })

        except Exception as exc:
            results.append({
                "webhook_id": hook["id"],
                "delivered": False,
                "error": str(exc)[:250],
            })

    return results


@app.post("/pipeline/run", status_code=202)
def run_pipeline(data: PipelineRequest, user=Depends(current_user)):
    with get_db() as db:
        requisition = db.execute(
            "SELECT * FROM requisitions WHERE id = ? AND tenant_id = ?",
            (data.requisition_id, user["tenant_id"]),
        ).fetchone()

        if not requisition:
            raise HTTPException(status_code=404, detail="Requisition not found")

        if data.candidate_ids:
            placeholders = ",".join("?" for _ in data.candidate_ids)
            candidates = db.execute(
                f"""SELECT * FROM candidates
                    WHERE tenant_id = ? AND id IN ({placeholders})""",
                [user["tenant_id"], *data.candidate_ids],
            ).fetchall()
        else:
            candidates = db.execute(
                "SELECT * FROM candidates WHERE tenant_id = ?",
                (user["tenant_id"],),
            ).fetchall()

        job_text = " ".join([
            requisition["title"] or "",
            requisition["description"] or "",
            requisition["department"] or "",
        ])

        workflow = run_agent_workflow(
            job_text,
            [dict(candidate) for candidate in candidates],
        )
        results = workflow["results"]
        run_id = str(uuid.uuid4())

        db.execute(
            """INSERT INTO pipeline_runs
               (id, tenant_id, requisition_id, results, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                run_id,
                user["tenant_id"],
                data.requisition_id,
                json.dumps(results),
                now(),
            ),
        )

    audit(user["tenant_id"], user["id"], workflow["audit_event"])
    return {
        "run_id": run_id,
        "status": "completed",
        "candidate_count": len(results),
        "results": results,
        "agent_trace": workflow["trace"],
        "scoring_method": "explainable_weighted_rules_v1",
        "note": (
            "LangGraph-orchestrated, transparent rule-based matching. "
            "Scores are not AI assessments or hiring recommendations."
        ),
    }


@app.get("/pipeline/status/{run_id}")
def pipeline_status(run_id: str, user=Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            """SELECT id, requisition_id, created_at FROM pipeline_runs
               WHERE id = ? AND tenant_id = ?""",
            (run_id, user["tenant_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Pipeline run not found")

    return {"run_id": row["id"], "status": "completed", "created_at": row["created_at"]}


@app.get("/pipeline/trace/{run_id}")
def pipeline_trace(run_id: str, user=Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            """SELECT * FROM pipeline_runs
               WHERE id = ? AND tenant_id = ?""",
            (run_id, user["tenant_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Pipeline run not found")

    results = json.loads(row["results"])
    default_steps = [
        {"step": name, "status": "completed"}
        for name in (
            "SkillsAgent", "CultureAgent", "RiskFlagAgent",
            "ExplainAgent", "AuditLogAgent",
        )
    ]
    steps = results[0].get("agent_trace", default_steps) if results else default_steps

    return {"run_id": row["id"], "steps": steps, "results": results}


@app.post("/eval/run", status_code=202)
def run_evaluation(data: EvaluationRequest, user=Depends(current_user)):
    with get_db() as db:
        candidate_count = db.execute(
            "SELECT COUNT(*) FROM candidates WHERE tenant_id = ?",
            (user["tenant_id"],),
        ).fetchone()[0]
        requisition_count = db.execute(
            "SELECT COUNT(*) FROM requisitions WHERE tenant_id = ?",
            (user["tenant_id"],),
        ).fetchone()[0]

        evaluation_id = str(uuid.uuid4())
        results = {
            "candidate_records": candidate_count,
            "requisition_records": requisition_count,
            "database_access": "passed",
            "evaluation_scope": "baseline_system_smoke_check",
            "rag_faithfulness": None,
            "answer_relevance": None,
            "bias_detection": None,
            "note": "AI quality metrics require a configured evaluation dataset and model pipeline.",
        }

        db.execute(
            "INSERT INTO evaluation_runs VALUES (?, ?, ?, ?, ?)",
            (
                evaluation_id,
                user["tenant_id"],
                data.name,
                json.dumps(results),
                now(),
            ),
        )

    audit(user["tenant_id"], user["id"], "evaluation.completed")
    return {"evaluation_id": evaluation_id, "status": "completed", "results": results}


@app.get("/eval/results/{evaluation_id}")
def evaluation_results(evaluation_id: str, user=Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            """SELECT * FROM evaluation_runs
               WHERE id = ? AND tenant_id = ?""",
            (evaluation_id, user["tenant_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Evaluation not found")

    return {
        "evaluation_id": row["id"],
        "name": row["name"],
        "created_at": row["created_at"],
        "results": json.loads(row["results"]),
    }


@app.post("/knowledge-base/documents", status_code=201)
def add_knowledge_document(data: KnowledgeDocument, user=Depends(current_user)):
    document_id = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            """INSERT INTO knowledge_documents
               VALUES (?, ?, ?, ?, ?)""",
            (
                document_id,
                user["tenant_id"],
                data.title,
                data.content,
                now(),
            ),
        )

    audit(user["tenant_id"], user["id"], "knowledge_document.created")
    return {"id": document_id, "title": data.title, "status": "stored"}


@app.get("/knowledge-base/stats")
def knowledge_base_stats(user=Depends(current_user)):
    with get_db() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM knowledge_documents WHERE tenant_id = ?",
            (user["tenant_id"],),
        ).fetchone()[0]

    return {
        "document_count": count,
        "storage": "sqlite",
        "search_method": "basic_text_match",
        "vector_search_configured": False,
    }


@app.get("/knowledge-base/search")
def search_knowledge_base(q: str, user=Depends(current_user)):
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty")

    pattern = f"%{q.strip()}%"
    with get_db() as db:
        rows = db.execute(
            """SELECT id, title, content, created_at
               FROM knowledge_documents
               WHERE tenant_id = ? AND (title LIKE ? OR content LIKE ?)
               ORDER BY created_at DESC LIMIT 20""",
            (user["tenant_id"], pattern, pattern),
        ).fetchall()

    return {"query": q, "count": len(rows), "results": [dict(row) for row in rows]}


@app.get("/candidates/{candidate_id}")
def get_candidate(candidate_id: str, user=Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            """SELECT id, name, email, skills, experience_years, created_at
               FROM candidates WHERE id = ? AND tenant_id = ?""",
            (candidate_id, user["tenant_id"]),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Candidate not found")

    result = dict(row)
    result["skills"] = [
        skill.strip() for skill in result["skills"].split(",") if skill.strip()
    ]
    return result


@app.delete("/candidates/{candidate_id}")
def delete_candidate(candidate_id: str, user=Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM candidates WHERE id = ? AND tenant_id = ?",
            (candidate_id, user["tenant_id"]),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Candidate not found")

        # Remove associated review records before deleting the candidate.
        db.execute(
            "DELETE FROM candidate_reviews WHERE candidate_id = ? AND tenant_id = ?",
            (candidate_id, user["tenant_id"]),
        )

        db.execute(
            "DELETE FROM candidates WHERE id = ? AND tenant_id = ?",
            (candidate_id, user["tenant_id"]),
        )

    audit(user["tenant_id"], user["id"], "candidate.deleted")
    deliver_webhook_event(
        user["tenant_id"],
        "candidate.deleted",
        {"candidate_id": candidate_id},
    )
    return {
        "id": candidate_id,
        "status": "deleted",
        "associated_reviews_deleted": True,
    }


@app.get("/requisitions/{requisition_id}/shortlist")
def requisition_shortlist(
    requisition_id: str,
    limit: int = 20,
    user=Depends(current_user),
):
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 100")

    with get_db() as db:
        requisition = db.execute(
            """SELECT id, title, department, description
               FROM requisitions WHERE id = ? AND tenant_id = ?""",
            (requisition_id, user["tenant_id"]),
        ).fetchone()

        if not requisition:
            raise HTTPException(status_code=404, detail="Requisition not found")

        candidates = db.execute(
            """SELECT id, name, email, skills, experience_years, created_at
               FROM candidates WHERE tenant_id = ?""",
            (user["tenant_id"],),
        ).fetchall()

    job_text = " ".join([
        requisition["title"],
        requisition["department"],
        requisition["description"],
    ]).lower()
    job_terms = set(job_text.replace(",", " ").replace(".", " ").split())

    results = []
    for candidate in candidates:
        skills = [
            item.strip() for item in candidate["skills"].split(",") if item.strip()
        ]
        matched = [
            skill for skill in skills
            if skill.lower() in job_terms
        ]
        score = round(len(matched) / len(skills) * 100, 1) if skills else 0

        results.append({
            "candidate_id": candidate["id"],
            "candidate_name": candidate["name"],
            "email": candidate["email"],
            "skills": skills,
            "matched_skills": matched,
            "experience_years": candidate["experience_years"],
            "match_score": score,
            "scoring_method": "basic_keyword_overlap_demo",
        })

    results.sort(key=lambda item: item["match_score"], reverse=True)
    audit(user["tenant_id"], user["id"], "requisition.shortlist.viewed")

    return {
        "requisition_id": requisition_id,
        "count": min(len(results), limit),
        "results": results[:limit],
        "note": "Demo keyword matching only; not an AI assessment or hiring recommendation.",
    }


# Resume-ingestion schema migration: preserve existing candidate records.
@app.on_event("startup")
def add_resume_columns():
    with get_db() as db:
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(candidates)")
        }
        if "resume_text" not in columns:
            db.execute(
                "ALTER TABLE candidates ADD COLUMN resume_text TEXT NOT NULL DEFAULT ''"
            )
        if "resume_filename" not in columns:
            db.execute(
                "ALTER TABLE candidates ADD COLUMN resume_filename TEXT NOT NULL DEFAULT ''"
            )


@app.post("/candidates/ingest", status_code=201)
async def ingest_resume(
    file: UploadFile = File(...),
    name: str = Form(default=""),
    email: str = Form(default=""),
    experience_years: float = Form(default=0),
    user=Depends(current_user),
):
    import re
    import pymupdf

    filename = (file.filename or "").strip()
    extension = Path(filename).suffix.lower()

    if extension not in {".pdf", ".txt"}:
        raise HTTPException(status_code=400, detail="Only PDF and TXT resumes are supported")

    content = await file.read(10 * 1024 * 1024 + 1)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Resume exceeds the 10 MB limit")

    if extension == ".pdf":
        if not content.startswith(b"%PDF"):
            raise HTTPException(status_code=400, detail="Invalid PDF file")
        try:
            with pymupdf.open(stream=content, filetype="pdf") as document:
                resume_text = "\n".join(page.get_text() for page in document)
        except Exception:
            raise HTTPException(status_code=400, detail="Unable to read PDF resume")
    else:
        try:
            resume_text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="TXT resume must use UTF-8 encoding")

    resume_text = resume_text.strip()
    if not resume_text:
        raise HTTPException(status_code=400, detail="No readable text found in resume")

    extracted_email = re.search(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        resume_text,
    )
    candidate_email = email.strip().lower() or (
        extracted_email.group(0).lower() if extracted_email else None
    )

    if candidate_email and not re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        candidate_email,
    ):
        raise HTTPException(status_code=400, detail="Invalid candidate email")

    candidate_name = name.strip()
    if not candidate_name:
        for line in resume_text.splitlines():
            line = line.strip()
            if line and not re.search(r"@", line) and len(line) <= 160:
                candidate_name = line
                break

    if not candidate_name:
        raise HTTPException(
            status_code=400,
            detail="Candidate name not found; provide the name in the upload form",
        )

    if len(candidate_name) > 160:
        raise HTTPException(status_code=400, detail="Candidate name is too long")

    if not 0 <= experience_years <= 70:
        raise HTTPException(status_code=400, detail="Experience must be between 0 and 70 years")

    skill_catalog = [
        "Python", "Java", "JavaScript", "TypeScript", "React", "Next.js",
        "Node.js", "FastAPI", "Django", "Flask", "SQL", "PostgreSQL",
        "MySQL", "MongoDB", "AWS", "Azure", "Docker", "Kubernetes",
        " machine learning", "Machine Learning", "TensorFlow", "PyTorch",
        "LangChain", "LangGraph", "Git", "Linux", "HTML", "CSS",
    ]
    normalized_text = resume_text.lower()
    skills = sorted({
        skill.strip()
        for skill in skill_catalog
        if skill.strip() and skill.strip().lower() in normalized_text
    })

    if experience_years == 0:
        experience_match = re.search(
            r"(\d+(?:\.\d+)?)\s*\+?\s*years?\s+(?:of\s+)?experience",
            normalized_text,
        )
        if experience_match:
            experience_years = min(float(experience_match.group(1)), 70)

    candidate_id = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            """INSERT INTO candidates
               (id, tenant_id, name, email, skills, experience_years,
                created_at, resume_text, resume_filename)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                candidate_id,
                user["tenant_id"],
                candidate_name,
                candidate_email,
                ", ".join(skills),
                experience_years,
                now(),
                resume_text,
                Path(filename).name[:255],
            ),
        )

    audit(user["tenant_id"], user["id"], "candidate.resume_ingested")
    deliver_webhook_event(
        user["tenant_id"],
        "candidate.created",
        {
            "candidate_id": candidate_id,
            "name": candidate_name,
            "email": candidate_email,
            "skills": skills,
            "experience_years": experience_years,
            "source": "resume_ingestion",
        },
    )
    return {
        "candidate_id": candidate_id,
        "name": candidate_name,
        "email": candidate_email,
        "skills": skills,
        "experience_years": experience_years,
        "resume_filename": Path(filename).name[:255],
        "extraction_method": "text_extraction_and_basic_pattern_matching",
        "note": "This is basic resume text extraction, not an AI assessment.",
    }
