def get_next_adaptive_scenario(all_scenarios, attempts, profile):
    if not all_scenarios:
        return None, "No scenarios available."

    if not attempts:
        return all_scenarios[0], "Initial Diagnostic: Evaluating your baseline cybersecurity vigilance."

    recent_scenario_ids = [a["scenario_id"] for a in attempts[-3:]]

    # Find category with highest vulnerability rate that has at least 1 attempt
    stats = profile.get("category_stats", {})
    target_category = None
    max_vuln = -1

    for cat, data in stats.items():
        if data.get("total", 0) > 0 and data.get("vuln", 0) > max_vuln:
            max_vuln = data.get("vuln", 0)
            target_category = cat

    # Also look for untried threat categories
    tested_categories = {a.get("category_code") for a in attempts}
    untested_threat_cats = [
        s["category_code"] for s in all_scenarios 
        if s["is_threat"] and s["category_code"] not in tested_categories
    ]

    candidate = None
    rationale = ""

    if max_vuln > 0 and target_category:
        # User has a known vulnerability: choose a scenario targeting it
        matching = [s for s in all_scenarios if s["category_code"] == target_category and s["id"] not in recent_scenario_ids]
        if matching:
            candidate = matching[0]
            rationale = f"Adaptive Remediation: High vulnerability detected in '{target_category}' ({max_vuln}%). Serving targeted reinforcement drill."

    if not candidate and untested_threat_cats:
        # Serve untested threat categories
        target_cat = untested_threat_cats[0]
        matching = [s for s in all_scenarios if s["category_code"] == target_cat]
        if matching:
            candidate = matching[0]
            rationale = f"Comprehensive Diagnostics: Evaluating untested attack vector '{target_cat}'."

    if not candidate:
        # Rotate to the least recently tested scenario
        attempted_ids = [a["scenario_id"] for a in attempts]
        unattempted = [s for s in all_scenarios if s["id"] not in attempted_ids]
        if unattempted:
            candidate = unattempted[0]
            rationale = "Skill Expansion: Exploring new multi-channel threat vector."
        else:
            # Pick scenario with oldest attempt
            oldest_id = attempts[0]["scenario_id"]
            matched = [s for s in all_scenarios if s["id"] != recent_scenario_ids[-1]]
            candidate = matched[0] if matched else all_scenarios[0]
            rationale = "Periodic Refresher: Re-evaluating vigilance across diverse attack pretexts."

    return candidate, rationale
