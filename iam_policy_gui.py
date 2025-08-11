import os, json, csv, tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

results = []

def analyze(p):
    f = []; s = p.get("Statement", [])
    if not isinstance(s, list): s = [s]
    for stmt in s:
        a, r, e, c = stmt.get("Action"), stmt.get("Resource"), stmt.get("Effect"), stmt.get("Condition", None)
        if a == "*" or (isinstance(a, list) and "*" in a): f.append("Unrestricted action: '*'")
        if r == "*": f.append("Unrestricted resource: '*'")
        if e == "Allow" and a == "*" and r == "*" and not c: f.append("FULL access (Allow '*' on '*' with no condition)")
    return f

def risk(f): return ["None", "Low", "Moderate", "High"][min(len(f), 3)]

def run():
    folder = filedialog.askdirectory(); output.delete(1.0, tk.END); results.clear()
    if not folder: return
    output.insert(tk.END, f"Scanning folder: {folder}\n\n")
    for f in os.listdir(folder):
        if not f.endswith(".json"): continue
        try:
            policy = json.load(open(os.path.join(folder, f)))
            v = analyze(policy); r = risk(v)
            output.insert(tk.END, f"[{f}] — Risk: {r}\n")
            [output.insert(tk.END, f"  - {x}\n") for x in v] if v else output.insert(tk.END, "  No issues found.\n")
            results.append([f, os.path.basename(folder), "No" if v else "Yes", r, "; ".join(v) or "None"])
            output.insert(tk.END, "\n")
        except Exception as e:
            results.append([f, os.path.basename(folder), "Error", "N/A", str(e)])
            output.insert(tk.END, f"[{f}] — Error: {e}\n\n")

def export():
    if not results:
        messagebox.showwarning("No Data", "Run an analysis first.")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save Audit Report As"
    )
    if not path: return
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Filename", "Folder", "Is Secure", "Risk Level", "Violations"])
        writer.writerows(results)
    messagebox.showinfo("Export Complete", f"Audit results saved to:\n{path}")

# GUI Setup
root = tk.Tk(); root.title("IAM Policy Analyzer"); root.geometry("800x800")

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

tk.Button(frame, text="Select Folder & Run Analysis", command=run).pack(pady=(0, 10))

output = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=('Consolas', 10))
output.pack(fill=tk.BOTH, expand=True)

tk.Button(root, text="Export Results to CSV", command=export).pack(pady=(5, 10))

root.mainloop()
