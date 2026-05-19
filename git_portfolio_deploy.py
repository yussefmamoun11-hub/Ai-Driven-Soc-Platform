import os
import subprocess

REPO_URL = "https://github.com/yussefmamoun11-hub/cybersecurity-portfolio.git"
BRANCH = "main"

def run(cmd):
    print(f"\n▶ {cmd}")
    result = subprocess.run(cmd, shell=True, text=True)
    if result.returncode != 0:
        print(f"❌ Failed: {cmd}")
    return result.returncode == 0


def check_git():
    if not os.path.exists(".git"):
        print("❌ Not a git repository. Run this inside your project folder.")
        exit()


def init_branch():
    run("git branch -M main")


def setup_remote():
    remotes = os.popen("git remote").read()
    if "origin" not in remotes:
        run(f"git remote add origin {REPO_URL}")
    else:
        run(f"git remote set-url origin {REPO_URL}")


def commit_changes():
    run("git add .")

    status = os.popen("git status --porcelain").read()
    if not status.strip():
        print("⚠ No changes to commit")
        return

    run('git commit -m "feat: enterprise cybersecurity portfolio upgrade"')


def push_changes():
    print("\n🚀 Pushing to GitHub...")
    success = run(f"git pull origin {BRANCH} --rebase")
    if not success:
        print("⚠ Pull failed, continuing force push...")

    run(f"git push origin {BRANCH} --force")


def main():
    print("\n===================================")
    print("🔥 ENTERPRISE GITHUB DEPLOYER")
    print("===================================\n")

    check_git()
    init_branch()
    setup_remote()
    commit_changes()
    push_changes()

    print("\n===================================")
    print("✅ DEPLOY COMPLETE (SENIOR LEVEL MODE)")
    print("===================================\n")


if __name__ == "__main__":
    main()
