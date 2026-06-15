import os
import shutil
from datetime import datetime

def save_pdf_to_desktop(pdf_path):
    # Desktop path في Ubuntu
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

    # اسم جديد للملف
    filename = f"SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    destination = os.path.join(desktop_path, filename)

    # نسخ الملف من مكانه إلى Desktop
    shutil.copy(pdf_path, destination)

    print(f"[✓] PDF saved to Desktop: {destination}")

    # (اختياري) فتح الملف تلقائيًا
    os.system(f'xdg-open "{destination}"')

    return destination


# =========================
# مثال استخدام مع النظام عندك
# =========================

def handle_attack_and_generate_report(result, pdf_path):
    """
    result = output من detection engine
    pdf_path = الملف اللي اتولد عندك أصلاً
    """

    if result.get("level") in ["HIGH", "CRITICAL"]:
        desktop_pdf = save_pdf_to_desktop(pdf_path)

        os.system('notify-send "SOC ALERT" "Critical attack detected - Report generated"')

        return desktop_pdf


# =========================
# مثال تشغيل سريع
# =========================

if __name__ == "__main__":
    result = {
        "level": "CRITICAL",
        "attacker_ip": "192.168.88.166",
        "fails": 14
    }

    pdf_path = "/path/to/your/generated_report.pdf"

    handle_attack_and_generate_report(result, pdf_path)
