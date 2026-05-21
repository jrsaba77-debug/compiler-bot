"""
SentinelNode: Telemetry Tracker and Anomaly Evaluation Engine
Architectural Paradigm: Object-Oriented Programming (Python)
"""

class UserSession:
    """Tracks identity characteristics and entry failure parameters."""
    def __init__(self, account_name, contact_email, origin_ip):
        self.account_name = account_name
        self.contact_email = contact_email
        self.origin_ip = origin_ip
        self.failed_attempts = 0

    def record_failed_login(self):
        """Increments the internal counter for tracking invalid access attempts."""
        self.failed_attempts += 1
        return self.failed_attempts

    def clear_failed_logins(self):
        """Resets the tracking index back to normal parameters."""
        self.failed_attempts = 0


class ThreatAssessmentEngine:
    """Evaluates security signals and applies isolation levels."""
    def __init__(self):
        self.risk_multiplier = 15

    def evaluate_session_risk(self, user, has_invalid_credentials):
        """Computes a real-time risk score from 0 to 100 based on session input data."""
        base_score = 0

        # Parameter 1: Credential Integrity Loop
        if has_invalid_credentials:
            total_faults = user.record_failed_login()
            base_score += total_faults * self.risk_multiplier
        else:
            # Low baseline score for clean, valid connections
            base_score += 10

        
        if not user.origin_ip.startswith("192.168"):
            base_score += 25

        final_calculated_score = min(max(base_score, 0), 100)
        return self.determine_system_action(final_calculated_score)

    def determine_system_action(self, score):
        """Applies explicit administrative rules based on the evaluated score."""
        if score >= 85:
            return {"score": score, "tier": "CRITICAL", "remediation": "Total System Lockout + Notify Admin"}
        elif score >= 65:
            return {"score": score, "tier": "HIGH", "remediation": "Block Source IP Address Vector"}
        elif score >= 35:
            return {"score": score, "tier": "MEDIUM", "remediation": "Print Warning Flag to System Console"}
        else:
            return {"score": score, "tier": "LOW", "remediation": "Authorize Session and Grant Workspace Entry"}


class OperationalDashboard:
    """Formats runtime diagnostics into clear, clean terminal layouts."""
    @staticmethod
    def display_telemetry(user, assessment):
        print("\n=== SENTINELNODE SECURITY DIAGNOSTICS ===")
        print(f"Target Account   : {user.account_name} ({user.contact_email})")
        print(f"Network Origin   : {user.origin_ip}")
        print(f"Evaluated Score  : {assessment['score']} / 100")
        print(f"Security Status  : [{assessment['tier']}]")
        print(f"Enforced Protocol: {assessment['remediation']}")
        print("=========================================")


# ============================================================================
# SYSTEM EXECUTION RUN (RUNNING TEST CASE SCENARIOS)
# ============================================================================
if __name__ == "__main__":
    evaluator = ThreatAssessmentEngine()

    # Scenario 1: Clean, Valid Authorized Entry (Internal network range)
    print("\n[Running Test Scenario 1: Valid Employee Sign-in]")
    employee = UserSession("marketing_lead", "lead@company.com", "192.168.1.45")
    test_1_result = evaluator.evaluate_session_risk(employee, has_invalid_credentials=False)
    OperationalDashboard.display_telemetry(employee, test_1_result)

    # Scenario 2: Brute-Force Attack Pattern (External network range)
    print("\n[Running Test Scenario 2: External Malicious Intrusion Attempts]")
    intruder = UserSession("root_administrator", "unknown@anonymous.org", "84.22.191.5")
    
    # Simulating sequential access failures
    evaluator.evaluate_session_risk(intruder, has_invalid_credentials=True)
    evaluator.evaluate_session_risk(intruder, has_invalid_credentials=True)
    evaluator.evaluate_session_risk(intruder, has_invalid_credentials=True)
    
    # Final breach containment attempt
    critical_result = evaluator.evaluate_session_risk(intruder, has_invalid_credentials=True)
    OperationalDashboard.display_telemetry(intruder, critical_result)
