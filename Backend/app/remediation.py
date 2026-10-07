def generate_remediation(finding_title: str, severity: str):
    title = finding_title.lower()
    severity = severity.lower()

    if "sql injection" in title:
        return {
            "remediation": "Use parameterized queries or prepared statements and validate all user input.",
            "recommended_actions": [
                "Replace dynamically constructed SQL queries",
                "Use parameterized queries",
                "Validate and sanitize user input",
                "Apply least-privilege database permissions",
                "Perform a security retest after remediation"
            ]
        }

    if "xss" in title or "cross site scripting" in title:
        return {
            "remediation": "Implement proper input validation and output encoding.",
            "recommended_actions": [
                "Validate user-controlled input",
                "Encode output before rendering",
                "Implement Content Security Policy",
                "Test all affected endpoints",
                "Perform a security retest"
            ]
        }

    if severity == "critical":
        return {
            "remediation": "Immediately investigate and remediate the critical security finding.",
            "recommended_actions": [
                "Isolate the affected asset if necessary",
                "Apply the required security patch",
                "Review related logs",
                "Verify that exploitation is no longer possible",
                "Perform a security retest"
            ]
        }

    if severity == "high":
        return {
            "remediation": "Prioritize remediation of this high-severity security finding.",
            "recommended_actions": [
                "Investigate the affected asset",
                "Apply the appropriate security fix",
                "Review related security logs",
                "Validate the fix",
                "Perform a security retest"
            ]
        }

    return {
        "remediation": "Investigate and remediate the identified security finding according to its risk level.",
        "recommended_actions": [
            "Investigate the affected asset",
            "Apply the appropriate security fix",
            "Validate the remediation",
            "Perform a security retest"
        ]
    }