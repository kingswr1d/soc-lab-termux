# Cybersecurity Career Break-In Roadmap
## No university qualification required

You're already ahead of most people trying this: you have a working Termux SOC lab, sample data, analysis scripts, and a concrete GitHub-style artifact. Most career changers never build anything real.

This roadmap assumes:
- No CS/IT degree
- You're currently employed and can dedicate 10–15 hours/week
- You're based in South Africa
- Budget: R5,000–R15,000 for exams over 2 years
- Goal: SOC analyst, then specialist

---

## Phase 0: Prove You Can Do the Work (Months 0–3)

**Goal:** Have tangible proof of skills before you apply anywhere.

**Week 1–2: Set up and document your lab**
- Your lab is already built at `~/soc-lab/`. If not, run the install script and generate logs.
- Record one screen video (Loom or built-in screen recorder on Android) of you:
  1. Running `python3 apache_analyzer.py`
  2. Identifying the top attacker IPs
  3. Explaining what a brute-force attack looks like in the SSH logs
- Keep it under 10 minutes. This is your interview opener.

**Week 3–4: CompTIA Security+**
- Study: Professor Messer (YouTube, free), Jason Dion practice tests (Udemy ~R200)
- Exam cost: ~R3,500–R4,000
- Why this first: It's the baseline cert most SA SOC jobs list. It doesn't require a degree, just exam money.

**Week 5–12: Daily hands-on practice**
- TryHackMe: complete "Pre-Security" and "SOC Level 1" paths (free tiers are enough)
- PortSwigger Web Security Academy: do all "SQL injection" and "XSS" labs
- Every week: write one finding from your lab into a text file and push it to GitHub (you can use Termux git)

**Deliverable by Month 3:**
- Security+ scheduled or passed
- GitHub repo with your Termux SOC lab + 3+ analysis reports
- 1 video of you analyzing logs
- LinkedIn: "Aspiring SOC Analyst | Building hands-on labs in Termux | Security+ candidate"

---

## Phase 1: Land the First Role (Months 3–12)

**Goal:** Get paid to do SOC work. Titles to target: SOC Analyst, Security Operations Analyst, Junior Security Analyst, IT Security Analyst.

**Month 3–5: CySA+ or eJPT**
- CySA+ (CompTIA Cybersecurity Analyst): ~R4,000 exam. More theory, better for government/corporate roles in SA.
- eJPT (eLearnSecurity Junior Penetration Tester): ~R3,000 exam. More practical, highly regarded by SA tech companies and MSPs.
- Pick one. CySA+ is safer for traditional SOC jobs.

**Month 4–8: Freelance bridges**
- Offer log analysis reports to small MSPs or e-commerce shops in SA.
- Pitch: "I analyze your server logs and produce a prioritized security findings report. R800 per report."
- Platforms: Upwork, local Facebook groups ("South African Freelancers", "Cybersecurity SA"), LinkedIn outreach.
- Goal: 2–3 clients paying R1,500–R3,000 each. This gets you real stories for interviews.

**Month 6–10: Bug bounty practice (optional but recommended)**
- HackerOne and Bugcrowd have free signup.
- Focus on low-hanging XSS, info disclosure, and misconfigurations.
- I can help you write professional reports once you find a bug.
- First bounty: R1,000–R8,000 (takes 20–40 hours of hunting). Not reliable income, but shows initiative.

**Month 9–12: Job applications**
- Target: SOC Tier 1 roles at SA banks, fintechs, managed security service providers, large corporates.
- Key employers in SA: Dimension Data, IBM, PwC Cyber, Deloitte Risk Advisory, local SOC providers like Internet Solutions, Comsec, SecureData.
- Required: Security+ (strongly preferred), CySA+ or eJPT (nice to have), GitHub/lab proof.
- Expected starting salary in SA: R15,000–R28,000/month.
- Remote options: US/EU small companies via LinkedIn, Andela, VanHack. $15–$25/hour possible if you pass technical assessments.

**Deliverable by Month 12:**
- First SOC role OR R8,000+/month freelance income
- 5+ GitHub repos actively maintained
- Network of 200+ cybersecurity professionals on LinkedIn
- Bank statement showing income in the field

---

## Phase 2: Career Growth (Years 1–3)

**Goal:** Move from SOC Tier 1 to Tier 2/3 or specialist.

**Year 1: Build depth**
- Cert: eCPPT or CRTO (~R8,000–R12,000). Hands-on red/blue team skills are valued in SA.
- Master your employer's SIEM (Splunk, QRadar, Sentinel). get certified if free training is offered.
- Volunteer for incident response tickets. Document your triage process.

**Year 2: Specialize**
Pick one lane SA is hiring for:
- **Cloud Security** (AWS Security Specialty or Azure Security Engineer) — SA migration boom
- **Incident Response / Forensics** — volatility, memory analysis
- **GRC / Compliance** (POPIA, ISO 27001, PCI-DSS) — banks and retailers pay well

**Year 3: Negotiate**
- After 2 years at a company, benchmark your salary against SA market rates.
- If you're at R30,000–R40,000, you're underpaid. Job-hopping to R45,000–R65,000 is normal.
- Remote contracting for EU/US clients can push you to $40–$100/hour while you're based in SA.

---

## Phase 3: Top Earners (Year 3+)

- **Security Consultant:** R80,000–R150,000+/month. You sell expertise, not time.
- **Interim Security Manager / Virtual CISO:** R10,000–R25,000/day for SMBs that can't hire full-time.
- **Training:** SA companies pay R5,000–R15,000/day for security awareness trainers.
- **Bug bounty full-time:** R40,000–R100,000/month if you're in the top 10% of hunters.

---

## SA-Specific Shortcuts

1. **POPIA knowledge is gold** — Study the Protection of Personal Information Act 2013. Many SA companies are panicking about compliance right now. Being the person who can audit their POPIA readiness = high hourly rate.

2. **Free government resources** — The South African Cyber Security Hub (cybersecurityhub.org.za) lists free training and bursaries. Check monthly.

3. **Low-cost certs with high ROI in SA:**
   - CompTIA Security+ (required by most SA SOC jobs)
   - eJPT (more practical, loved by SA tech firms)
   - CRTO (red team ops, fast-growing demand)
   - ISO 27001 Lead Auditor (if going GRC route)

4. **Target employers who don't require degrees:**
   - Tech startups (Yoco, Jumo, SweepSouth)
   - MSPs and MSSPs (they hire on skill, not paper)
   - Banks' security operations (they need bulk SOC staff)
   - Remote-first EU/US small-medium businesses

5. **Networking in SA:**
   - Join South African Cyber Security Hub Slack/LinkedIn
   - Attend BSides Cape Town/Johannesburg (usually free)
   - Join ISACA South Africa chapters (student/professional member)

---

## Your Immediate Next 7 Days

| Day | Action |
|:----|:-------|
| 1 | Push your SOC lab to GitHub (I can help format the repo) |
| 2 | Register for TryHackMe, complete Room 1–3 of SOC Level 1 |
| 3 | Book your Security+ exam (scheduling creates urgency) |
| 4 | Write a 200-word "About" for LinkedIn: currently head chef, building SOC skills in Termux |
| 5 | Update CV to highlight transferable skills: inventory control = asset management, kitchen costs = budget security, team training = security awareness |
| 6 | Find 3 SA cybersecurity professionals on LinkedIn and send connection requests with personal notes |
| 7 | Join one SA cybersecurity community (Slack, Telegram, or LinkedIn group) and introduce yourself |

---

## The Hard Truth

You don't need a degree. You need:
1. Proof you can do the job (GitHub + video + certs)
2. Someone willing to give you a chance (small company, MSP, or remote client)
3. Ability to pass a technical test (study labs and practice questions)

Your lab is already proof. The next 3 months are about converting that proof into interviews.
