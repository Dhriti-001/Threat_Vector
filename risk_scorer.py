import numpy as np
from sklearn.ensemble import RandomForestClassifier
from feature_extractor import extract_scenario_features

CATEGORIES = ['URGENCY', 'AUTHORITY', 'FAKELINKS', 'INCENTIVE', 'COERCION']

CATEGORY_NAMES = {
    'URGENCY': 'Urgency & Time Pressure',
    'AUTHORITY': 'Authority Impersonation',
    'FAKELINKS': 'Fake Links & Typosquatting',
    'INCENTIVE': 'Reward & Greed Traps',
    'COERCION': 'Fear & Disciplinary Coercion',
    'LEGITIMATE': 'Authentic Institutional Context'
}

# Baseline trained RandomForest model on synthetic social engineering features
X_sample = np.array([
    [4, 2, 0, 0, 0, 0, 1, 0],  # Urgency attack
    [1, 5, 0, 0, 0, 0, 1, 0],  # Authority attack
    [2, 0, 0, 0, 1, 0, 1, 1],  # Typosquatting / link attack
    [1, 0, 4, 0, 0, 0, 1, 1],  # Incentive attack
    [2, 3, 0, 4, 1, 1, 0, 0],  # Coercion attack
    [0, 1, 0, 0, 0, 0, 1, 0],  # Safe newsletter
    [3, 3, 0, 0, 0, 0, 0, 0],  # Urgency chat attack
    [0, 0, 0, 0, 0, 0, 1, 0],  # Safe registration confirmation
])
y_sample = np.array([1, 1, 1, 1, 1, 0, 1, 0])

_ml_classifier = RandomForestClassifier(n_estimators=30, random_state=42)
_ml_classifier.fit(X_sample, y_sample)

def predict_threat_probability(text, channel='email', sender=''):
    feats = np.array([extract_scenario_features(text, channel, sender)])
    prob = _ml_classifier.predict_proba(feats)[0][1]
    return round(float(prob) * 100, 1)

def calculate_user_risk_profile(attempts):
    if not attempts:
        return {
            "composite_risk_score": 50.0,
            "primary_weakness": "Baseline (Not yet evaluated)",
            "category_stats": {c: {"total": 0, "failed": 0, "vuln": 0} for c in CATEGORIES},
            "total_tests": 0,
            "accuracy_pct": 0.0,
            "risk_level": "Unrated (Baseline)"
        }

    total_tests = len(attempts)
    correct_count = sum(1 for a in attempts if a["is_correct"])
    accuracy_pct = round((correct_count / total_tests) * 100, 1)

    category_stats = {}
    highest_vuln_cat = None
    highest_vuln_rate = -1

    for cat in CATEGORIES:
        cat_attempts = [a for a in attempts if a.get("category_code") == cat]
        total_cat = len(cat_attempts)
        if total_cat > 0:
            failed_cat = sum(1 for a in cat_attempts if not a["is_correct"])
            vuln_pct = round((failed_cat / total_cat) * 100)
            category_stats[cat] = {
                "total": total_cat,
                "failed": failed_cat,
                "vuln": vuln_pct
            }
            if vuln_pct > highest_vuln_rate:
                highest_vuln_rate = vuln_pct
                highest_vuln_cat = cat
        else:
            category_stats[cat] = {"total": 0, "failed": 0, "vuln": 0}

    # Calculate weighted composite risk score
    weights = {'URGENCY': 0.25, 'AUTHORITY': 0.20, 'FAKELINKS': 0.25, 'INCENTIVE': 0.15, 'COERCION': 0.15}
    weighted_vuln_sum = 0.0
    active_weights = 0.0

    for cat, w in weights.items():
        if cat in category_stats and category_stats[cat]["total"] > 0:
            weighted_vuln_sum += category_stats[cat]["vuln"] * w
            active_weights += w

    if active_weights > 0:
        base_score = weighted_vuln_sum / active_weights
    else:
        base_score = 100.0 - accuracy_pct

    # Dwell time factor: hasty decisions on incorrect attempts increase risk
    avg_speed = sum(a.get("response_time_sec", 5.0) for a in attempts) / total_tests
    speed_factor = 5.0 if avg_speed < 3.0 else 0.0
    composite_score = min(100.0, max(0.0, round(base_score + speed_factor, 1)))

    if composite_score < 30.0:
        risk_level = "Low Risk (Vigilant 🛡️)"
    elif composite_score < 65.0:
        risk_level = "Moderate Risk (Cautious ⚠️)"
    else:
        risk_level = "High Risk (Vulnerable 🚨)"

    if highest_vuln_cat and highest_vuln_rate > 0:
        primary_weakness = f"{CATEGORY_NAMES.get(highest_vuln_cat, highest_vuln_cat)} ({highest_vuln_rate}% vulnerability)"
    elif total_tests > 0 and accuracy_pct == 100.0:
        primary_weakness = "None Identified (Strong Vigilance)"
    else:
        primary_weakness = "Baseline (Not yet evaluated)"

    return {
        "composite_risk_score": composite_score,
        "primary_weakness": primary_weakness,
        "category_stats": category_stats,
        "total_tests": total_tests,
        "accuracy_pct": accuracy_pct,
        "risk_level": risk_level
    }
