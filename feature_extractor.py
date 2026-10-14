import re

URGENCY_KEYWORDS = [
    'immediate', 'immediately', 'urgent', 'urgently', 'expires', 'expire',
    'suspended', 'suspend', 'warning', 'critical', 'terminate', 'act now',
    'within 24 hours', 'within 60 seconds', 'promptly', 'deadline'
]

AUTHORITY_KEYWORDS = [
    'dean', 'director', 'board', 'judicial', 'investigation', 'disciplinary',
    'administration', 'executive', 'chief', 'security department', 'it support',
    'legal notice', 'summons', 'official', 'provost'
]

INCENTIVE_KEYWORDS = [
    'grant', 'stipend', 'won', 'award', 'free', 'bonus', 'claim', 'cash',
    'subsidy', 'token', 'congratulations', 'voucher', 'selected', 'prize'
]

COERCION_KEYWORDS = [
    'malpractice', 'plagiarism', 'infraction', 'hearing', 'expulsion',
    'prosecution', 'penalty', 'complaint', 'allegation', 'suspension',
    'lawsuit', 'violation'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.cc', '.buzz', '.monster', '.live']

def extract_scenario_features(text, channel='email', sender=''):
    text_lower = text.lower()
    sender_lower = sender.lower()
    
    urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    authority_count = sum(1 for kw in AUTHORITY_KEYWORDS if kw in text_lower)
    incentive_count = sum(1 for kw in INCENTIVE_KEYWORDS if kw in text_lower)
    coercion_count = sum(1 for kw in COERCION_KEYWORDS if kw in text_lower)
    
    has_suspicious_tld = 1 if any(tld in text_lower or tld in sender_lower for tld in SUSPICIOUS_TLDS) else 0
    has_exe_or_script = 1 if re.search(r'\.(exe|vbs|bat|scr|pdf\.exe)', text_lower) else 0
    has_external_link = 1 if ('http://' in text_lower or 'https://' in text_lower) else 0
    has_money_mention = 1 if ('$' in text or 'fee' in text_lower or 'payment' in text_lower) else 0
    
    return [
        urgency_count,
        authority_count,
        incentive_count,
        coercion_count,
        has_suspicious_tld,
        has_exe_or_script,
        has_external_link,
        has_money_mention
    ]
