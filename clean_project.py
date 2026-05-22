import os
import shutil

print("\n[+] CLEANING SOC PROJECT...\n")

# الملفات الغير مطلوبة (root junk)
files_to_remove = [
    "portfolio_builder.py",
    "enterprise_readme_upgrader.py",
    "git_portfolio_deploy.py",
    "GITHUB_BIO.txt",
    "README_BACKUP.md"
]

# folders غير مهمة (لو موجودة)
folders_to_remove = [
    "__pycache__",
]

# حذف الملفات
for file in files_to_remove:
    if os.path.exists(file):
        os.remove(file)
        print(f"[REMOVED] {file}")

# حذف الفولدرات
for folder in folders_to_remove:
    if os.path.exists(folder):
        shutil.rmtree(folder)
        print(f"[REMOVED] {folder}/")

print("\n[+] KEEPING ONLY CORE PROJECT STRUCTURE:")
print("    src/")
print("    README.md")
print("    requirements.txt (if exists)")

print("\n[+] CLEANUP DONE ✔")
