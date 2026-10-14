from ml_engine.risk_scorer import predict_threat_probability

BIAS_INFO = {
    "URGENCY": {
        "title": "Urgency & Artificial Time Compression",
        "description": "Attackers exploit panic and artificial deadlines so users bypass critical deliberation.",
        "defense": "Take a 30-second breather. Authentic administrative or IT issues are never resolved through a rushed countdown link."
    },
    "AUTHORITY": {
        "title": "Authority & Hierarchical Compliance Bias",
        "description": "Attackers disguise themselves as executives, deans, or directors to exploit natural deference.",
        "defense": "Inspect the raw email header domain. Never transfer money, buy gift cards, or divulge credentials solely based on unverified email requests."
    },
    "FAKELINKS": {
        "title": "Lookalike Domains & Visual Deception",
        "description": "Attackers craft lookalike URLs (.xyz/.top) or smishing links to steal credentials.",
        "defense": "Hover over hyperlinks and verify full URLs. Never follow tracking links in unsolicited SMS messages."
    },
    "INCENTIVE": {
        "title": "Incentive / Greed Trap Bias",
        "description": "Offers of free tech grants, prizes, or cash lure victims into entering banking details.",
        "defense": "If you did not apply for an award, grant, or lottery, you did not win it. Discard unsolicited monetary promises."
    },
    "COERCION": {
        "title": "Fear, Intimidation & Coercion",
        "description": "Threatens legal action, academic expulsion, or penalties to coerce reckless attachments download.",
        "defense": "Verify via official physical campus channels. Never execute double-extension files (e.g. .pdf.exe) sent via email."
    },
    "LEGITIMATE": {
        "title": "Authentic Institutional Communication",
        "description": "Legitimate communication with verified domain headers and standard informational guidance.",
        "defense": "Maintain healthy situational awareness while recognizing authentic official communications."
    }
}

def generate_explainable_feedback(scenario, user_choice, is_correct, response_time):
    is_threat = scenario.get("is_threat", False)
    cat_code = scenario.get("category_code", "LEGITIMATE")
    
    if is_threat and user_choice:
        verdict = "Threat Neutralized! (Correctly Identified)"
        alert_type = "success"
        verdict_desc = "Excellent vigilance! You spotted the malicious pretext and avoided the trap."
    elif not is_threat and not user_choice:
        verdict = "Verified Legitimate! (Accurate Assessment)"
        alert_type = "success"
        verdict_desc = "Accurate! You recognized authentic communication without raising a false alarm."
    elif is_threat and not user_choice:
        verdict = "Vulnerability Exploited! (Fell for Threat)"
        alert_type = "danger"
        verdict_desc = "Warning: You marked a dangerous social engineering attack as safe. You would have been compromised."
    else:
        verdict = "False Positive Flagged"
        alert_type = "warning"
        verdict_desc = "Caution: This communication was genuine, but you flagged it as a threat."

    ml_confidence = predict_threat_probability(
        scenario.get("body", "") + " " + scenario.get("subject", ""),
        scenario.get("channel", "email"),
        scenario.get("sender", "")
    )
    if not is_threat:
        ml_confidence = round(100.0 - ml_confidence, 1)

    if response_time < 2.5:
        speed_insight = f"Rapid decision ({response_time:.1f}s): Hasty decisions under urgency significantly increase phishing vulnerability."
    elif response_time > 12.0:
        speed_insight = f"Deliberate inspection ({response_time:.1f}s): Good careful reading, but ensure key indicators like sender domains are checked first."
    else:
        speed_insight = f"Balanced inspection ({response_time:.1f}s): Optimal deliberate evaluation time."

    vector_data = BIAS_INFO.get(cat_code, BIAS_INFO["LEGITIMATE"])

    return {
        "is_correct": is_correct,
        "verdict": verdict,
        "alert_type": alert_type,
        "verdict_desc": verdict_desc,
        "confidence_score": ml_confidence,
        "speed_insight": speed_insight,
        "attack_vector_info": vector_data,
        "red_flags": scenario.get("red_flags", []),
        "explanation": scenario.get("explanation", ""),
        "micro_lesson": scenario.get("micro_lesson", "")
    }
