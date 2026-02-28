import os
import httpx
import json
import logging
from typing import Optional

logger = logging.getLogger("scanner.llm")

class LLMService:
    """
    Service for integrating Generative AI (OpenAI GPT) for expert security analysis.
    Two main capabilities:
    1. generate_payload: AI-powered payload generation for scan-time testing
    2. generate_audit_content: Structured professional remediation report per vulnerability
    """
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.enabled = bool(self.api_key)

    async def _call_gpt(self, system_prompt: str, user_prompt: str,
                         model: str = "gpt-3.5-turbo",
                         response_json: bool = False,
                         max_tokens: int = 500) -> Optional[str]:
        """Internal helper: calls OpenAI and returns the response text."""
        if not self.enabled:
            return None
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": max_tokens,
            }
            if response_json:
                payload["response_format"] = {"type": "json_object"}

            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.post(
                    self.api_url,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"].strip()
                logger.warning(f"OpenAI returned {resp.status_code}: {resp.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"OpenAI call failed: {e}")
            return None

    async def generate_payload(self, method: str, path: str, ep_metadata: dict) -> Optional[dict]:
        """
        Calls OpenAI to generate a contextually relevant and potentially vulnerable payload.
        Used at scan-time to test API endpoints with realistic data.
        """
        if not self.enabled or method not in ["POST", "PUT", "PATCH"]:
            return None

        system = "You are a specialized API security payload generator. Return only valid JSON."
        user = f"""Role: API Security Pentester
Task: Generate a realistic JSON payload for a security test on the following endpoint.

Endpoint: {method} {path}
Metadata/Schema: {ep_metadata}

Requirements:
1. The payload must look like valid application data.
2. Include common fields that might be found in such an endpoint.
3. For security testing, occasionally include sensitive fields (like 'role', 'is_admin', 'permissions') if they seem relevant to the context.

Return ONLY valid JSON."""

        raw = await self._call_gpt(system, user, response_json=True, max_tokens=300)
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                return None
        return None

    async def generate_audit_content(self, vuln_type: str, endpoint: str, evidence: str) -> Optional[dict]:
        """
        Generates a complete, structured professional remediation report for one vulnerability.

        Prompt Design Philosophy:
        - Chain-of-thought: Ask GPT to reason step-by-step (impact → root cause → fix → code → compliance)
        - Role anchoring: Set GPT as a senior security auditor to keep tone professional
        - JSON-enforced output: Forces structured response for reliable template rendering
        - Context-rich input: Include vuln_type + endpoint semantics + evidence for accurate analysis
        - Compliance mapping: Automatically maps to OWASP / PCI-DSS / GDPR

        Returns a dict with keys:
          business_impact, root_cause, technical_analysis,
          remediation_steps, code_example, references, compliance_standards
        """
        if not self.enabled:
            return None

        system_prompt = """You are a senior API security auditor and penetration tester with 10+ years of experience.
You write clear, actionable, professional security audit reports for development teams.
Your reports must be educational and help developers understand WHY a vulnerability exists and HOW to fix it.
Always reason through: (1) what happened, (2) why it's dangerous, (3) how to fix it with concrete code.
Return ONLY valid JSON matching the requested schema."""

        user_prompt = f"""You detected the following API security vulnerability during an automated security audit.
Generate a complete professional remediation report section for this finding.

=== VULNERABILITY DETAILS ===
Type: {vuln_type}
Affected Endpoint: {endpoint}
Evidence / Proof of Concept: {evidence}

=== YOUR TASK ===
Analyze this vulnerability and return a JSON object with exactly these keys:

{{
  "business_impact": "2-3 sentences explaining the real-world business risk if this is exploited. Focus on data breach, compliance violation, or financial loss. Write in third person.",
  "root_cause": "1-2 sentences explaining the technical root cause of this specific vulnerability at {endpoint}.",
  "technical_analysis": "2-3 sentences of technical explanation: what HTTP behavior revealed this vulnerability, what the attacker can do step-by-step.",
  "remediation_steps": "4-6 numbered actionable steps that a developer can follow to fix this exact vulnerability. Be specific to the endpoint and vuln type.",
  "code_example": "A short, practical code snippet (in Python/FastAPI or pseudocode) showing the CORRECT way to implement authorization for this endpoint. Use code fences.",
  "compliance_standards": "List 2-3 relevant compliance frameworks (e.g., OWASP API3:2023, PCI-DSS Req 6.4, GDPR Art.25) with a one-line explanation of how this finding relates to each.",
  "priority": "Immediate / High / Medium / Low — based on exploitability and impact"
}}

Be specific to the endpoint '{endpoint}' and vulnerability type '{vuln_type}'. Do not give generic advice."""

        raw = await self._call_gpt(system_prompt, user_prompt, response_json=True, max_tokens=900)
        if raw:
            try:
                return json.loads(raw)
            except Exception as e:
                logger.warning(f"Failed to parse AI audit JSON: {e}. Raw: {raw[:200]}")
                # Return plain text fallback
                return {"remediation_steps": raw, "business_impact": "", "root_cause": "",
                        "technical_analysis": "", "code_example": "", "compliance_standards": "", "priority": "High"}
        return None
