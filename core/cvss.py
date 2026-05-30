# core/cvss.py
from cvss import CVSS3
from typing import Dict, Tuple

class CVSSCalculator:
    """
    Calculates CVSS v3.1 Base Score.
    Metrics: Attack Vector (AV), Complexity (AC), Privileges (PR), 
    User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I), Availability (A).
    """
    
    @staticmethod
    def calculate(metrics: Dict[str, str]) -> Tuple[float, str]:
        """
        Calculate score based on metric dict.
        Example input: {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"}
        """
        # Construct Vector String
        vector = f"CVSS:3.1/AV:{metrics.get('AV', 'N')}/AC:{metrics.get('AC', 'L')}/" \
                 f"PR:{metrics.get('PR', 'L')}/UI:{metrics.get('UI', 'N')}/" \
                 f"S:{metrics.get('S', 'C')}/C:{metrics.get('C', 'H')}/" \
                 f"I:{metrics.get('I', 'H')}/A:{metrics.get('A', 'H')}"
                 
        try:
            cvss = CVSS3(vector)
            score = cvss.scores()[0]  # Base Score
            severity = "CRITICAL" if score >= 9.0 else \
                       "HIGH" if score >= 7.0 else \
                       "MEDIUM" if score >= 4.0 else \
                       "LOW" if score >= 0.1 else "NONE"
            return round(score, 1), severity
        except Exception as e:
            return 0.0, "UNKNOWN"

    @staticmethod
    def get_recommended_metrics(vuln_type: str) -> Dict[str, str]:
        """Returns default metrics for common vulnerability types"""
        defaults = {
            "SQL Injection": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
            "Reflected XSS": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
            "Broken Access Control": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            "Info Leak": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
        }
        return defaults.get(vuln_type, {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"})
