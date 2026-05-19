def build_profile(name, role, skills, focus):

    bio = f"""
{role} | Cybersecurity & Software Engineering Enthusiast

Focused on {focus} with strong interest in building scalable security tools and automation systems.

Skills include:
{", ".join(skills)}

Passionate about real-world problem solving, security systems, and automation.
"""

    readme = f"""
# {name} - GitHub Portfolio

## 🚀 About Me
I am a {role} focused on building practical systems in cybersecurity and software engineering.

My main focus is:
- {focus}

## 🧠 Skills
{chr(10).join([f"- {s}" for s in skills])}

## 🔐 Interests
- Security Automation
- Red Team / Blue Team Concepts
- System Design
- Tool Development

## 📌 Goal
Building real-world impactful projects that simulate industry-level security and engineering systems.
"""

    # 🔥 Save files automatically
    with open("GITHUB_BIO.txt", "w") as f:
        f.write(bio)

    with open("README.md", "w") as f:
        f.write(readme)

    print("\n✅ Files created successfully:")
    print("- GITHUB_BIO.txt")
    print("- README.md")


if __name__ == "__main__":
    build_profile(
        name="Your Name",
        role="Cybersecurity Engineer",
        skills=[
            "Python",
            "Linux",
            "Networking",
            "Security Tools",
            "Log Analysis"
        ],
        focus="SOC automation, threat detection, and red team simulation"
    )
