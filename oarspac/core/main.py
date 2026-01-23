import json
import re
import sys
from pathlib import Path
from ospac import PolicyRuntime
from ospac.models.compliance import ActionType

from ..report.cli import format_compliance_report


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
                # print(f"Non-compliant package: {path}\nresult: {r}\n{license_info}")

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
