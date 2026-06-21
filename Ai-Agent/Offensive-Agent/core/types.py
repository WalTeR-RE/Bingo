from enum import Enum


class VulnType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    FILE_UPLOAD = "file_upload"
    BRUTE_FORCE = "brute_force"
    SSTI = "ssti"
    XXE = "xxe"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    DESERIALIZATION = "insecure_deserialization"
    AUTH_BYPASS = "authentication_bypass"
    RACE_CONDITION = "race_condition"
    MISCONFIGURATION = "misconfiguration"
    OTHER = "other"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"


class ScanPhase(str, Enum):
    RECON = "recon"
    WEB_ANALYSIS = "web_analysis"
    DISCOVERY = "discovery"
    ROUTING = "routing"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
