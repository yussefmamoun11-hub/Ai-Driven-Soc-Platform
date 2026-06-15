import os
from pathlib import Path

ROOT = Path.cwd()

print("\n[+] SOC PROJECT BOOTSTRAP STARTING...\n")

# 1. Ensure structure
folders = [
    "src/soc_tool",
    "src/detection_engine",
    "src/core",
    "data",
    "tests",
    "docs"
]

for f in folders:
    Path(f).mkdir(parents=True, exist_ok=True)
    print(f"[+] Ensured folder: {f}")

# 2. Create __init__.py files
for f in ["src/soc_tool", "src/detection_engine", "src/core"]:
    init_file = Path(f) / "__init__.py"
    init_file.touch(exist_ok=True)
    print(f"[+] Created: {init_file}")

# 3. Detect attack engine file
possible_paths = [
    "src/soc_tool/attack_engine.py",
    "src/soc_tool/soc_attack.py"
]

attack_path = None
for p in possible_paths:
    if Path(p).exists():
        attack_path = p
        break

if not attack_path:
    print("[-] No attack engine found!")
else:
    print(f"[+] Found attack engine: {attack_path}")

# 4. Create MAIN entry point
main_content = f"""from {attack_path.replace('/', '.').replace('.py','')} import main as attack_main

def banner():
    print(\"\"\"
=====================================
    SOC SIMULATION PLATFORM
    Auto Generated Bootstrap
=====================================
\"\"\")

def main():
    banner()
    print("[+] Running SOC simulation...\n")
    attack_main()

if __name__ == "__main__":
    main()
"""

main_file = ROOT / "main.py"
main_file.write_text(main_content)

print("[+] Created main.py entry point")

# 5. Create requirements.txt if missing
req = ROOT / "requirements.txt"
if not req.exists():
    req.write_text("python3\n")
    print("[+] Created requirements.txt")

# 6. Git helper instructions
print("\n[+] NEXT STEPS:")
print("1. Run: python3 main.py")
print("2. git add .")
print("3. git commit -m 'refactor: enterprise SOC bootstrap'")
print("4. git push\n")

print("[+] DONE - PROJECT READY 🚀\n")
