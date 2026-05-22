from src.soc_tool.attack_engine import main as attack_main

def banner():
    print("""
=====================================
    SOC SIMULATION PLATFORM
    Auto Generated Bootstrap
=====================================
""")

def main():
    banner()
    print("[+] Running SOC simulation...\n")
    attack_main()

if __name__ == "__main__":
    main()
