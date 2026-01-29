from datetime import date
from collections import Counter
from ospac.models.compliance import ActionType

def _clean_package_path(path: str):
    # split string by the first "node_modules"
    parts = path.split("node_modules", 1)
    if len(parts) > 1:
        path = parts[1]
    return path


def format_compliance_report(reports):

    # Initialize data structures
    total_packages = len(reports)
    license_type_counts = Counter()
    license_id_counts = Counter()
    action_issues = []

    # Categorize packages
    for report in reports:
        name = report["name"]
        licenses = report["licenses"]
        licenses_and_types = report["licenses_and_types"]
        action = report["report"].action

        # Count license types (use most restrictive if multiple)
        if licenses_and_types:
            # Get all license types for this package
            types = [lt["license_type"] for lt in licenses_and_types]
            # Priority: NO-ASSERTION > copyleft_strong > copyleft_weak > proprietary > permissive > public_domain
            priority = {
                "NO-ASSERTION": 0,
                "copyleft_strong": 1,
                "copyleft_weak": 2,
                "proprietary": 3,
                "permissive": 4,
                "public_domain": 5,
            }
            most_restrictive = min(types, key=lambda t: priority.get(t, 0))
            license_type_counts[most_restrictive] += 1

            # Count individual licenses
            for lic in licenses:
                license_id_counts[lic] += 1

        # Collect action items for non-compliant packages
        if action in [
            ActionType.DENY,
            ActionType.FLAG_FOR_REVIEW,
            ActionType.CONTAMINATE,
        ]:
            action_issues.append(
                {
                    "name": name,
                    "licenses": licenses,
                    "licenses_and_types": licenses_and_types,
                    "action": action,
                    "report": report["report"],
                    "package": report["package"],
                }
            )
        elif licenses_and_types and any(
            lt["license_type"] == "NO-ASSERTION" for lt in licenses_and_types
        ):
            # Also flag NO-ASSERTION even if action is ALLOW
            action_issues.append(
                {
                    "name": name,
                    "licenses": licenses,
                    "licenses_and_types": licenses_and_types,
                    "action": action,
                    "report": report["report"],
                    "package": report["package"],
                }
            )

    # Determine overall status
    has_blockers = any(
        issue["action"] in [ActionType.DENY, ActionType.CONTAMINATE]
        or any(
            lt["license_type"] == "NO-ASSERTION" for lt in issue["licenses_and_types"]
        )
        for issue in action_issues
    )
    has_warnings = any(
        issue["action"] == ActionType.FLAG_FOR_REVIEW for issue in action_issues
    )

    if has_blockers:
        status_badge = "⚠ Action required"
        final_status = "NOT CLEARED FOR PRODUCTION"
    elif has_warnings:
        status_badge = "⚠ Review needed"
        final_status = "CONDITIONAL - REVIEW REQUIRED"
    else:
        status_badge = "✓ Compliant"
        final_status = "CLEARED FOR PRODUCTION"

    # Build the report
    lines = []
    lines.append("OSS License Compliance Report")
    lines.append(f"Generated: {date.today().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"Total dependencies: {total_packages}")
    lines.append(f"Status: {status_badge}")
    lines.append("")

    # License breakdown
    lines.append("LICENSE BREAKDOWN")

    # Group licenses by type category
    type_groups = {
        "permissive": "Permissive licenses",
        "copyleft_weak": "Weak copyleft licenses",
        "copyleft_strong": "Strong copyleft licenses",
        "public_domain": "Public domain",
        "proprietary": "Proprietary licenses",
        "NO-ASSERTION": "Unknown/Undeclared",
    }

    # Display in order of restrictiveness
    type_order = [
        "permissive",
        "public_domain",
        "copyleft_weak",
        "copyleft_strong",
        "proprietary",
        "NO-ASSERTION",
    ]
    displayed_types = [t for t in type_order if license_type_counts[t] > 0]

    for idx, license_type in enumerate(displayed_types):
        count = license_type_counts[license_type]
        percentage = (count / total_packages * 100) if total_packages > 0 else 0
        is_last = idx == len(displayed_types) - 1
        prefix = "└─" if is_last else "├─"

        lines.append(
            f"{prefix} {type_groups[license_type]}: {count}/{total_packages} ({percentage:.0f}%)"
        )

        # Show specific licenses under each type
        type_licenses = {}
        for report in reports:
            for lt in report["licenses_and_types"]:
                if lt["license_type"] == license_type:
                    lic_id = lt["license"]
                    if lic_id not in type_licenses:
                        type_licenses[lic_id] = 0
                    type_licenses[lic_id] += 1

        sorted_licenses = sorted(type_licenses.items(), key=lambda x: (-x[1], x[0]))
        for lic_idx, (lic_id, lic_count) in enumerate(sorted_licenses):
            is_last_lic = lic_idx == len(sorted_licenses) - 1
            if is_last:
                lic_prefix = "   └─" if is_last_lic else "   ├─"
            else:
                lic_prefix = "│  └─" if is_last_lic else "│  ├─"
            lines.append(f"{lic_prefix} {lic_id}: {lic_count}")

    lines.append("")

    # Action items
    if action_issues:
        lines.append("ACTION ITEMS")

        # Group by severity
        denied = [i for i in action_issues if i["action"] == ActionType.DENY]
        contaminated = [
            i for i in action_issues if i["action"] == ActionType.CONTAMINATE
        ]
        review_needed = [
            i for i in action_issues if i["action"] == ActionType.FLAG_FOR_REVIEW
        ]
        no_assertion = [
            i
            for i in action_issues
            if i["action"]
            not in [ActionType.DENY, ActionType.CONTAMINATE, ActionType.FLAG_FOR_REVIEW]
            and any(
                lt["license_type"] == "NO-ASSERTION" for lt in i["licenses_and_types"]
            )
        ]

        if denied:
            lines.append(
                f"🚫 {len(denied)} package{'s' if len(denied) != 1 else ''} with denied licenses:"
            )
            for idx, issue in enumerate(denied, 1):
                licenses_str = ", ".join(issue["licenses"])
                lines.append(f"  {idx}. {issue['name']} - {licenses_str}")
                if issue["report"].message:
                    lines.append(f"     → {issue['report'].message}")
                if issue["report"].remediation:
                    lines.append(f"     → {issue['report'].remediation}")
                lines.append(f"     → {_clean_package_path(issue['package'])}")
                lines.append("")

        if contaminated:
            lines.append(
                f"⚠️  {len(contaminated)} package{'s' if len(contaminated) != 1 else ''} with contamination risk:"
            )
            for idx, issue in enumerate(contaminated, 1):
                licenses_str = ", ".join(issue["licenses"])
                lines.append(f"  {idx}. {issue['name']} - {licenses_str}")
                if issue["report"].message:
                    lines.append(f"     → {issue['report'].message}")
                if issue["report"].remediation:
                    lines.append(f"     → {issue['report'].remediation}")
                lines.append(f"     → {_clean_package_path(issue['package'])}")
                lines.append("")

        if no_assertion:
            lines.append(
                f"⚠ {len(no_assertion)} package{'s' if len(no_assertion) != 1 else ''} require license investigation:"
            )
            for idx, issue in enumerate(no_assertion, 1):
                lines.append(f"  {idx}. {issue['name']} - {licenses_str}")
                if issue["report"].message:
                    lines.append(f"     → {issue['report'].message}")
                if issue["report"].remediation:
                    lines.append(f"     → {issue['report'].remediation}")
                lines.append(f"     → {_clean_package_path(issue['package'])}")
                lines.append(f"     → {issue}")
                lines.append(f"  {idx}. {issue['name']} - NO LICENSE ASSERTION")
                lines.append(f"     → Check package.json and source repository")
                lines.append(f"     → Verify with maintainer if needed")
                lines.append("")

        if review_needed:
            lines.append(
                f"📋 {len(review_needed)} package{'s' if len(review_needed) != 1 else ''} flagged for review:"
            )
            for idx, issue in enumerate(review_needed, 1):
                licenses_str = ", ".join(issue["licenses"])
                lines.append(f"  {idx}. {issue['name']} - {licenses_str}")
                if issue["report"].message:
                    lines.append(f"     → {issue['report'].message}")
                if issue["report"].remediation:
                    lines.append(f"     → {issue['report'].remediation}")
                lines.append(f"     → {_clean_package_path(issue['package'])}")

    # Final compliance status
    lines.append(f"COMPLIANCE STATUS: {final_status}")
    if has_blockers:
        blocker_count = len(
            [
                i
                for i in action_issues
                if i["action"] in [ActionType.DENY, ActionType.CONTAMINATE]
                or any(
                    lt["license_type"] == "NO-ASSERTION"
                    for lt in i["licenses_and_types"]
                )
            ]
        )
        lines.append(
            f"Blocker: {blocker_count} package{'s' if blocker_count != 1 else ''} with critical issues must be resolved"
        )
    elif has_warnings:
        lines.append(
            f"Warning: {len(review_needed)} package{'s' if len(review_needed) != 1 else ''} require manual review before production deployment"
        )

    return "\n".join(lines)
