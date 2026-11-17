"""Transparent LangGraph workflow for TalentMind candidate matching."""

import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph


SKILL_ALIASES = {
    "Python": ["python"],
    "Java": ["java"],
    "JavaScript": ["javascript", "js"],
    "TypeScript": ["typescript"],
    "SQL": ["sql", "structured query language"],
    "PostgreSQL": ["postgresql", "postgres"],
    "MySQL": ["mysql"],
    "MongoDB": ["mongodb", "mongo db"],
    "FastAPI": ["fastapi"],
    "Django": ["django"],
    "Flask": ["flask"],
    "React": ["react", "react.js"],
    "Next.js": ["next.js", "nextjs"],
    "Node.js": ["node.js", "nodejs"],
    "AWS": ["aws", "amazon web services"],
    "Azure": ["azure", "microsoft azure"],
    "GCP": ["gcp", "google cloud platform"],
    "Docker": ["docker"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Terraform": ["terraform"],
    "Git": ["git"],
    "Linux": ["linux"],
    "Redis": ["redis"],
    "Qdrant": ["qdrant"],
    "Pandas": ["pandas"],
    "NumPy": ["numpy"],
    "TensorFlow": ["tensorflow"],
    "PyTorch": ["pytorch"],
    "LangChain": ["langchain"],
    "LangGraph": ["langgraph"],
    "Machine Learning": ["machine learning", "ml"],
    "Deep Learning": ["deep learning"],
    "REST APIs": ["rest api", "rest apis", "restful api"],
    "GraphQL": ["graphql"],
    "CI/CD": ["ci/cd", "continuous integration"],
}


class WorkflowState(TypedDict, total=False):
    job_text: str
    candidates: list[dict]
    required_skills: list[str]
    required_years: float | None
    results: list[dict]
    trace: list[dict]
    audit_event: str


def _record(state: WorkflowState, name: str, **updates):
    trace = list(state.get("trace", []))
    trace.append({"step": name, "status": "completed"})
    return {"trace": trace, **updates}


def skills_agent(state: WorkflowState):
    job_text = state["job_text"]
    required_skills = []

    for canonical, aliases in SKILL_ALIASES.items():
        for alias in aliases:
            pattern = (
                r"(?<![a-zA-Z0-9+#.])"
                + re.escape(alias)
                + r"(?![a-zA-Z0-9+#.])"
            )
            if re.search(pattern, job_text, re.IGNORECASE):
                required_skills.append(canonical)
                break

    years_match = re.search(
        r"(?:minimum\s+|at least\s+)?(\d+(?:\.\d+)?)\s*\+?\s*years?",
        job_text,
        re.IGNORECASE,
    )
    required_years = float(years_match.group(1)) if years_match else None

    results = []
    for candidate in state.get("candidates", []):
        candidate_skills = []
        for skill in (candidate.get("skills") or "").split(","):
            skill = skill.strip()
            if not skill:
                continue
            normalized = skill.lower()
            canonical = next(
                (
                    name for name, aliases in SKILL_ALIASES.items()
                    if normalized == name.lower() or normalized in aliases
                ),
                skill,
            )
            if canonical not in candidate_skills:
                candidate_skills.append(canonical)

        matched = [s for s in required_skills if s in candidate_skills]
        missing = [s for s in required_skills if s not in candidate_skills]
        candidate_years = float(candidate.get("experience_years") or 0)

        skill_score = (
            len(matched) / len(required_skills) * 100
            if required_skills else None
        )
        experience_score = (
            min(candidate_years / required_years, 1.0) * 100
            if required_years and required_years > 0 else None
        )

        components = []
        if skill_score is not None:
            components.append((skill_score, 0.75))
        if experience_score is not None:
            components.append((experience_score, 0.25))

        if components:
            total_weight = sum(weight for _, weight in components)
            score = sum(value * weight for value, weight in components) / total_weight
        else:
            score = 0.0

        results.append({
            "candidate_id": candidate["id"],
            "candidate_name": candidate["name"],
            "candidate_skills": candidate_skills,
            "required_skills": required_skills,
            "matched_skills": matched,
            "missing_skills": missing,
            "experience_years": candidate_years,
            "required_experience_years": required_years,
            "skill_score": round(skill_score, 1) if skill_score is not None else None,
            "experience_score": round(experience_score, 1) if experience_score is not None else None,
            "match_score": round(score, 1),
            "scoring_method": "explainable_weighted_rules_v1",
        })

    results.sort(key=lambda item: item["match_score"], reverse=True)
    return _record(
        state,
        "SkillsAgent",
        required_skills=required_skills,
        required_years=required_years,
        results=results,
    )


def culture_agent(state: WorkflowState):
    # No subjective or protected-trait inference. No role-specific criteria
    # are currently stored in the requisition schema, so culture is not scored.
    results = []
    for item in state.get("results", []):
        updated = dict(item)
        updated["culture_assessment"] = {
            "status": "not_assessed",
            "reason": "No explicit, job-related work-style criteria were supplied.",
            "score_impact": 0,
        }
        results.append(updated)
    return _record(state, "CultureAgent", results=results)


def risk_flag_agent(state: WorkflowState):
    results = []
    for item in state.get("results", []):
        updated = dict(item)
        flags = []
        if not updated["candidate_skills"]:
            flags.append("candidate_skills_not_provided")
        if not updated["required_skills"] and updated["required_experience_years"] is None:
            flags.append("job_requirements_not_recognized")
        updated["risk_flags"] = flags
        results.append(updated)
    return _record(state, "RiskFlagAgent", results=results)


def explain_agent(state: WorkflowState):
    results = []
    for item in state.get("results", []):
        explanations = []
        if item["required_skills"]:
            explanations.append(
                f"Matched {len(item['matched_skills'])} of "
                f"{len(item['required_skills'])} recognized required skills."
            )
        else:
            explanations.append(
                "No recognizable skills were found in the job description."
            )

        if item["required_experience_years"] is not None:
            explanations.append(
                f"Candidate has {item['experience_years']:g} years of experience; "
                f"the job specifies {item['required_experience_years']:g} years."
            )

        if item["risk_flags"]:
            explanations.append("Review flags: " + ", ".join(item["risk_flags"]) + ".")
        explanations.append(
            "Culture fit was not assessed and did not affect the score."
        )

        updated = dict(item)
        updated["explanation"] = " ".join(explanations)
        updated["agent_explanations"] = {
            "SkillsAgent": "Compared recognized job skills and experience.",
            "CultureAgent": "Not assessed; no explicit job-related criteria were supplied.",
            "RiskFlagAgent": (
                ", ".join(item["risk_flags"]) if item["risk_flags"] else "No data-quality flags."
            ),
            "ExplainAgent": "Produced a transparent explanation of the rule-based score.",
        }
        results.append(updated)

    return _record(state, "ExplainAgent", results=results)


def audit_log_agent(state: WorkflowState):
    trace = list(state.get("trace", []))
    trace.append({"step": "AuditLogAgent", "status": "completed"})
    results = []
    for item in state.get("results", []):
        updated = dict(item)
        updated["agent_trace"] = trace
        results.append(updated)
    return {
        "trace": trace,
        "results": results,
        "audit_event": "pipeline.completed",
    }


_builder = StateGraph(WorkflowState)
_builder.add_node("skills", skills_agent)
_builder.add_node("culture", culture_agent)
_builder.add_node("risk_flags", risk_flag_agent)
_builder.add_node("explain", explain_agent)
_builder.add_node("audit_log", audit_log_agent)
_builder.add_edge(START, "skills")
_builder.add_edge("skills", "culture")
_builder.add_edge("culture", "risk_flags")
_builder.add_edge("risk_flags", "explain")
_builder.add_edge("explain", "audit_log")
_builder.add_edge("audit_log", END)
_workflow = _builder.compile()


def run_agent_workflow(job_text: str, candidates: list[dict]) -> dict:
    return _workflow.invoke({
        "job_text": job_text,
        "candidates": candidates,
        "trace": [],
    })
