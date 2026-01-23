import json
from pprint import pprint
import re
import sys
from pathlib import Path
from ospac import PolicyRuntime
from ospac.models.compliance import ActionType


class ReportStatus:
    def __init__(self, report):
        self.report = report

    def __repr__(self):
        return f"{self.report["name"]} | {self.report["licenses"]}"

    def __dict__(self):
        return {
            "package": self.report["package"],
            "name": self.report["name"],
            "licenses": self.report["licenses"],
            "action": self.report["report"].action.value,
        }


def prepare_statistics(reports):
    stats = {
        "total_packages": 0,
        "allowed": [],
        "denied": [],
        "needs_review": [],
        "approve": [],
        "contaminate": [],
    }
    for report in reports:
        stats["total_packages"] += 1
        r = report["report"]
        section = None
        if r.action == ActionType.ALLOW:
            section = "allowed"
        elif r.action == ActionType.DENY:
            section = "denied"
        elif r.action == ActionType.FLAG_FOR_REVIEW:
            section = "needs_review"
        elif r.action == ActionType.APPROVE:
            section = "approve"
        elif r.action == ActionType.CONTAMINATE:
            section = "contaminate"

        status = ReportStatus(report)
        stats[section].append(status)
    return stats


def format_compliance_report(reports):
    from datetime import date
    from collections import defaultdict, Counter

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
                lines.append("")

        if no_assertion:
            lines.append(
                f"⚠ {len(no_assertion)} package{'s' if len(no_assertion) != 1 else ''} require license investigation:"
            )
            for idx, issue in enumerate(no_assertion, 1):
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
                lines.append("")

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


def format_reports(reports):
    formatted = []
    for report in reports:
        package = report["package"]
        licenses = ", ".join(report["licenses"])
        action = report["report"].action.value
        actions_str = action
        formatted.append(
            f"Package: {package}\n  Licenses: {licenses}\n  Actions: {actions_str}\n"
        )
    return "\n".join(formatted)


def evaluate_license_compliance(
    kissbom_path, policy_path=Path(__file__).parent.parent.parent / "policies"
):
    is_compliant = True
    runtime = PolicyRuntime.from_path(policy_path)

    # Parse kissbom.json
    with open(kissbom_path, "r") as f:
        sbom = json.load(f)

    reports = []
    # Evaluate each package for license compliance
    for package in sbom["packages"]:
        license = package.get("license")
        all_licenses = package.get("all_licenses", [])
        path = package.get("path")
        name = package.get("name")

        if path == ".":
            continue

        normalized_licenses = list(
            set(
                [
                    re.sub(r"(-only|-or-later)$", "", lic).strip()
                    for lic in [license] + all_licenses
                ]
            )
        )

        # Derive license types from licenses for policy evaluation
        licenses_and_types = []
        for lic in normalized_licenses:
            lic_type = None
            try:
                lic_type = (
                    runtime.lookup_license_data(lic)
                    .get("license")
                    .get("type", "NO-ASSERTION")
                )
            except:
                lic_type = "NO-ASSERTION"

            licenses_and_types.append({"license": lic, "license_type": lic_type})

        _r = []
        for license_info in licenses_and_types:
            r = runtime.evaluate(license_info)
            _r.append(r)
            if r.action != ActionType.ALLOW:
                is_compliant = False
                print(f"Non-compliant package: {path}\nresult: {r}\n{license_info}")

        reports.append(
            {
                "package": path,
                "name": name,
                "licenses": normalized_licenses,
                "licenses_and_types": licenses_and_types,
                "report": r.aggregate(_r),
            }
        )

    print(format_compliance_report(reports))
    return is_compliant


if __name__ == "__main__":
    is_compliant = evaluate_license_compliance("./__tests__/kissbom.v1.json")
    sys.exit(0 if is_compliant else 1)
