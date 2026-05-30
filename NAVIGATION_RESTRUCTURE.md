# إعادة هيكلة التنقّل — Agentic‑IAM

هذا الملف يطبّق التغييرات التي اقترحتها: تجميع الموديولات المتداخلة وثمّة خريطة ربط بينها وبين الصفحات/الدوال الحالية في المشروع (بدون تغييرات على الواجهة).

## الملخّص المقترح (نهج نهائي)

🏠 Home

💊 Health

🔐 Identity & Agents
  - User Management
  - Browse Agents
  - Register Agent

🛡️ Security Operations
  - Alert Center
  - Incident Response
  - System Monitor

🔎 Investigation Center
  - Activity Timeline
  - Attack Forensics

⚡ Automation & AI
  - Automation Center
  - AI Assistant

📊 Analytics & Reports

🛡️ Risk & Compliance
  - Risk Assessment
  - Audit Logs

🔐 Access & Policies

🧠 Zero Trust Engine
🤖 Agent Trust & Behavior

⚙️ System Config

## خريطة الربط إلى الصفحات/الدوال الموجودة حالياً

- Home
  - `show_home()` — [app.py](app.py)

- Health
  - `show_page_health_center()` — [app.py](app.py#L2649)

- Identity & Agents
  - User Management: `show_page_user_management()` — [app.py](app.py#L2182)
  - Browse Agents: `show_page_browse_agents()` — [app.py](app.py#L1642)
  - Register Agent: `show_page_register_agent()` — [app.py](app.py#L1652)
    - أزرار/فورم التسجيل في: [dashboard/components/agent_management.py](dashboard/components/agent_management.py) و[dashboard/components/agent_selection.py](dashboard/components/agent_selection.py)

- Security Operations
  - Alert Center: `show_page_alert_center()` — [app.py](app.py#L3082)
  - Incident Response: `show_page_incident_response()` — [app.py](app.py#L1739)
  - System Monitor: `show_page_system_monitor()` — [app.py](app.py#L2361)

- Investigation Center
  - Activity Timeline: `show_page_activity_timeline()` — [app.py](app.py#L2688)
  - Attack Forensics: `show_page_attack_forensics()` — [app.py](app.py#L2928)

- Automation & AI
  - Automation Center: `show_page_automation_center()` — [app.py](app.py#L3634)
  - AI Assistant: components in [dashboard/components/ai_assistant.py](dashboard/components/ai_assistant.py)

- Analytics & Reports
  - Reports page: `show_page_reports()` — [app.py](app.py#L1914)
  - Analytics page: `show_page_analytics()` — [app.py](app.py#L2492)
  - API report endpoints: [api/main.py](api/main.py)

- Risk & Compliance
  - Risk assessment helpers: `audit_compliance.py`
  - Audit logs + exporter: `audit_exporter.py`, `audit/blockchain.py`

- Access & Policies
  - Authorization/Enforcer: `authorization.py`, `authz.py`, `casbin_model.conf`

- Zero Trust Engine (مكوّن مقترح)
  - يمكن ربط نقاط التحقق المستمر بأماكن: مصادقة (`authentication.py`), جلسات (`agent_identity.py`), و`agent_intelligence.py` لحساب مؤشرات الثقة.

- Agent Trust & Behavior
  - `agent_intelligence.py` و`agent_intelligence_train.py` — حساب الثقة، كشف الشذوذ، تدريب النماذج.

- System Config
  - `show_page_system_config()` — [app.py](app.py#L2361)

## التوصيات للخطوات التالية (بدون تعديل الواجهة)

1. توثيق داخلي في README/Docs (تمّ هنا).
2. إنشاء ملفات backend placeholders للموديولات الجديدة (Access & Policies, Zero Trust, Agent Trust, Investigation center) بحيث لا تتداخل مع الواجهات الحالية.
3. تحديث خرائط الراوت الداخلية (إن وُجدت مراجع حرفية) لربط الخدمات الجديدة دون تغيير النصوص الظاهرة للمستخدم.
4. إضافة اختبارات تكامل تغطي سلوك الموديولات المجمعة حديثاً.

## جملة العرض (تستخدم قدّام الدكاترة)

"We reduced redundancy by grouping overlapping modules into logical domains like Security Operations and Investigation Center, improving system clarity and scalability."

---
ملف هذا هو المرجع التنفيذي لتنفيذ ما طلبتَ؛ لو تأذن أبدأ بإنشاء الـ backend scaffolds (ملفات placeholder) للموديولات الجديدة الآن؟
