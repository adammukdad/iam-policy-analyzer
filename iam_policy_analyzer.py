import os, json, csv

def load_policy(path): return json.load(open(path))

def analyze_policy(policy):
    findings, stmts = [], policy.get("Statement", [])
    if not isinstance(stmts, list): stmts = [stmts]
    for stmt in stmts:
        a, r, e, c = stmt.get("Action"), stmt.get("Resource"), stmt.get("Effect"), stmt.get("Condition", None)
        if a == "*" or (isinstance(a, list) and "*" in a): findings.append("Unrestricted action: '*'")
        if r == "*": findings.append("Unrestricted resource: '*'")
        if e == "Allow" and a == "*" and r == "*" and not c: findings.append("FULL access (Allow '*' on '*' with no condition)")
    return findings

def risk_level(f): return ["None", "Low", "Moderate", "High"][min(len(f), 3)]

def scan_folder(name, data):
    print(f"\n=== Scanning {name} ===")
    for file in os.listdir(name):
        if not file.endswith(".json"): continue
        try:
            policy = load_policy(os.path.join(name, file))
            findings = analyze_policy(policy)
            risk = risk_level(findings)
            print(f"\n[{file}] — Risk: {risk}")
            [print(f"  - {v}") for v in findings] if findings else print("  No issues found.")
            data.append([file, name, "No" if findings else "Yes", risk, "; ".join(findings) or "None"])
        except Exception as e:
            print(f"  Error reading {file}: {e}")
            data.append([file, name, "Error", "N/A", f"Error reading file: {e}"])

if __name__ == "__main__":
    rows = [["Filename", "Folder", "Is Secure", "Risk Level", "Violations"]]
    [scan_folder(f, rows) for f in ["test_policies", "secure_policies"]]
    with open("iam_audit_report.csv", "w", newline='') as f: csv.writer(f).writerows(rows)
    print("\n✅ Results exported to iam_audit_report.csv")
