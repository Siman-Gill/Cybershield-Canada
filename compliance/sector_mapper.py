# compliance/sector_mapper.py
# Maps each threat to Canadian law requirements and produces a compliance report

def get_compliance_requirements(sector: str, severity: str) -> dict:
    """
    Given a sector and severity, return the Canadian compliance obligations.
    This is the code that differentiates you from other candidates.
    """
    requirements = {
        "applicable_laws": [],
        "notification_required": False,
        "notification_deadline_hours": None,
        "notify_who": [],
        "regulatory_body": None
    }

    if sector == "healthcare":
        requirements["applicable_laws"]   = ["PHIPA", "PIPEDA"]
        requirements["regulatory_body"]   = "Information and Privacy Commissioner of Ontario"
        if severity in ["critical", "high"]:
            requirements["notification_required"]        = True
            requirements["notification_deadline_hours"]  = 72
            requirements["notify_who"] = [
                "Chief Privacy Officer",
                "IPC Ontario (within 72 hours)",
                "Affected individuals (if PHI confirmed)"
            ]

    elif sector == "banking":
        requirements["applicable_laws"]   = ["OSFI B-10", "PIPEDA", "PCI-DSS"]
        requirements["regulatory_body"]   = "Office of the Superintendent of Financial Institutions"
        if severity in ["critical", "high"]:
            requirements["notification_required"]        = True
            requirements["notification_deadline_hours"]  = 24
            requirements["notify_who"] = [
                "OSFI (within 24 hours for cyber incidents)",
                "Chief Risk Officer",
                "Payment card networks (if cardholder data affected)"
            ]

    elif sector == "government":
        requirements["applicable_laws"]   = ["ITSG-33", "Privacy Act", "PIPEDA"]
        requirements["regulatory_body"]   = "Treasury Board Secretariat / Canadian Centre for Cyber Security"
        if severity == "critical":
            requirements["notification_required"]        = True
            requirements["notification_deadline_hours"]  = 1
            requirements["notify_who"] = [
                "Canadian Centre for Cyber Security (CCCS)",
                "Departmental Security Officer",
                "Treasury Board Secretariat"
            ]

    else:  # IT sector
        requirements["applicable_laws"]   = ["PIPEDA"]
        requirements["regulatory_body"]   = "Office of the Privacy Commissioner of Canada"
        if severity in ["critical", "high"]:
            requirements["notification_required"]        = True
            requirements["notification_deadline_hours"]  = 72
            requirements["notify_who"] = ["Office of the Privacy Commissioner"]

    return requirements

def compliance_summary(sector: str, severity: str) -> str:
    """Return a one-line compliance summary string"""
    req = get_compliance_requirements(sector, severity)
    laws = ", ".join(req["applicable_laws"])
    if req["notification_required"]:
        return (f"Applicable: {laws} | "
                f"Notification required within {req['notification_deadline_hours']}h | "
                f"Notify: {req['notify_who'][0]}")
    return f"Applicable: {laws} | Monitoring only"

# Test it directly: python compliance/sector_mapper.py
if __name__ == "__main__":
    test_cases = [
        ("healthcare", "critical"),
        ("banking", "high"),
        ("government", "critical"),
        ("it", "medium")
    ]
    print("\n=== CANADIAN COMPLIANCE ASSESSMENT ===\n")
    for sector, sev in test_cases:
        print(f"Sector: {sector.upper()} | Severity: {sev.upper()}")
        print(f"  {compliance_summary(sector, sev)}\n")
