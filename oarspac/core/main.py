import json
import re
import sys
from unicodedata import name
from ospac import PolicyRuntime
from ospac.models.compliance import ActionType


def evaluate_license_compliance(kissbom_path, policy_path="policies/"):
    is_compliant = True
    runtime = PolicyRuntime.from_path(policy_path)

    # Parse kissbom.json
    with open(kissbom_path, "r") as f:
        sbom = json.load(f)

    # Evaluate each package for license compliance
    for package in sbom["packages"]:
        license = package.get("license")
        all_licenses = package.get("all_licenses", [])
        name = package.get("path") or package.get("name")

        if name == ".":
            continue

        normalized_licenses = [
            re.sub(r"(-only|-or-later)$", "", lic).strip()
            for lic in [license] + all_licenses
        ]

        print("Evaluating package:", name, normalized_licenses)

        result = runtime.evaluate(
            {
                "licenses": normalized_licenses,
            }
        )

        print(result.action)
        if result.action != ActionType.ALLOW:
            is_compliant = False
            print(f"Non-compliant package: {name}\nresult: {result}\n")

    return is_compliant


if __name__ == "__main__":
    is_compliant = evaluate_license_compliance("./__tests__/kissbom.v1.json")
    sys.exit(0 if is_compliant else 1)
