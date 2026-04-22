# 📚 دليل الملفات والمكونات - Agentic-IAM

## نظرة عامة

هذا الملف يشرح كل ملف مهم في المشروع والغرض منه وكيفية استخدامه.

---

## 🔴 الملفات الأساسية في الجذر (Root Level)

### `authentication.py` - التحقق من الهوية
**الهدف**: التحقق من بيانات الوكيل

```python
"""
المسؤوليات:
✓ التحقق من صحة البيانات (API key, Certificate, Token)
✓ حساب درجة الثقة
✓ تسجيل محاولات المصادقة
✓ منع الهجمات (حد المحاولات)

الدوال الرئيسية:
- authenticate() - التحقق من بيانات
- verify_credential() - التحقق من صحة البيانات
- calculate_trust_level() - حساب درجة الثقة
"""
```

**مثال الاستخدام**:
```python
auth_manager = AuthenticationManager()
result = await auth_manager.authenticate(
    agent_id="agent-001",
    credentials={"api_key": "secret"},
    method="api_key"
)

if result.success:
    print(f"✅ Trust level: {result.trust_level}")
```

---

### `authorization.py` - التفويض والصلاحيات
**الهدف**: الحكم على ما يُسمح للوكيل فعله

```python
"""
المسؤوليات:
✓ التحقق من الصلاحيات (RBAC - Role Based)
✓ التحقق من القواعس المتقدمة (ABAC - Attribute Based)
✓ تقييم السياق (البيئة، الوقت، المكان)
✓ تسجيل قرارات التفويض

الدوال الرئيسية:
- authorize() - التحقق من الصلاحية
- check_permission() - فحص صلاحية واحدة
- get_agent_permissions() - الحصول على كل الصلاحيات
"""
```

**مثال الاستخدام**:
```python
auth_mgr = AuthorizationManager()
decision = await auth_mgr.authorize(
    agent_id="agent-001",
    resource="file://data",
    action="read"
)

if decision.allow:
    # قراءة الملف
```

---

### `agent_identity.py` - إدارة هويات الوكلاء
**الهدف**: إنشاء وإدارة هويات فريدة لكل وكيل

```python
"""
المكونات:
1. AgentIdentity - هوية الوكيل الواحد
   - معرّف فريد
   - مفاتيح عام وخاص
   - بيانات وصفية

2. AgentIdentityManager - إدارة الهويات
   - إنشاء هويات جديدة
   - تخزين الهويات
   - البحث عن هوية

3. AuthenticationResult - نتيجة التحقق
4. AuthenticationManager - مدير التحقق
5. AuthorizationManager - مدير التفويض
"""
```

**مثال الاستخدام**:
```python
# إنشاء هوية جديدة
identity = AgentIdentity.generate(
    agent_id="my-agent",
    metadata={"type": "llm"}
)

print(f"🔑 Public: {identity.get_public_key()}")
print(f"🔐 Private: {identity.get_private_key()}")
```

---

### `session_manager.py` - إدارة الجلسات
**الهدف**: تتبع وإدارة جلسات الوكلاء

```python
"""
المسؤوليات:
✓ إنشاء جلسات جديدة
✓ التحقق من صحة الجلسة
✓ إدارة انتهاء الصلاحية
✓ الكشف عن الأنشطة المريبة
✓ تنظيف الجلسات المنتهية

الدوال الرئيسية:
- create_session() - بدء جلسة جديدة
- validate_session() - التحقق من صحة
- end_session() - إنهاء الجلسة
- renew_session() - تجديد الصلاحية
"""
```

**مثال الاستخدام**:
```python
session = await session_mgr.create_session(
    agent_id="agent-001",
    metadata={"ip": "192.168.1.1"}
)

# التحقق لاحقاً
is_valid = await session_mgr.validate_session(session.session_id)
```

---

### `credential_manager.py` - إدارة البيانات
**الهدف**: إدارة آمنة لبيانات اعتماد الوكياء

```python
"""
المسؤوليات:
✓ إنشاء بيانات عشوائية آمنة
✓ التخزين الآمن (مشفر)
✓ التدوير التلقائي للبيانات
✓ إبطال البيانات المنتهية
✓ استرجاع البيانات بأمان

الدوال الرئيسية:
- create_credential() - إنشاء جديدة
- get_credential() - استرجاع البيانات
- rotate_credential() - تدوير (جديدة + إبطال قديمة)
- revoke_credential() - إبطال فوري
"""
```

**مثال الاستخدام**:
```python
# إنشاء بيانات جديدة
cred = await cred_mgr.create_credential(
    agent_id="agent-001",
    credential_type="api_key",
    ttl_days=90  # صلاحية 90 يوم
)

# استخدام البيانات
secret = await cred_mgr.get_credential(cred.credential_id)

# تدوير البيانات
await cred_mgr.rotate_credential(cred.credential_id)
```

---

### `federated_identity.py` - الربط الخارجي
**الهدف**: ربط هويات الوكلاء مع أنظمة خارجية

```python
"""
المسؤوليات:
✓ الربط مع Azure AD, AWS IAM, Okta, إلخ
✓ المزامنة مع الأنظمة الخارجية
✓ التحقق من التوقيعات
✓ إدارة الثقة بين الأنظمة
✓ تحديث الصلاحيات من الخارج

الدوال الرئيسية:
- federate_identity() - ربط هوية محلية بخارجية
- validate_federated_token() - التحقق من token
- sync_permissions() - مزامنة الصلاحيات
"""
```

**مثال الاستخدام**:
```python
# ربط مع Azure AD
identity = await fed_mgr.federate_identity(
    agent_id="agent-001",
    provider="azure_ad",
    external_id="00000000-0000-0000-0000-000000000000"
)
```

---

### `transport_binding.py` - أمان النقل
**الهدف**: تأمين الاتصالات بين الوكيل والنظام

```python
"""
المسؤوليات:
✓ تفعيل mTLS (تشفير متبادل)
✓ التحقق من الشهادات
✓ إدارة مفاتيح التشفير
✓ دعم الخوارزميات الآمنة الحديثة
✓ منع هجمات النقل

الدوال الرئيسية:
- verify_client_certificate() - التحقق من شهادة العميل
- establish_mtls_connection() - بناء اتصال آمن
- get_cipher_suites() - الخوارزميات المدعومة
"""
```

---

### `audit_compliance.py` - التسجيل والامتثال
**الهدف**: تسجيل شامل لجميع العمليات والامتثال للقوانين

```python
"""
المكونات:
1. AuditManager - تسجيل الأحداث
   - من فعل ماذا ومتى
   - نجح أم فشل
   - التفاصيل الكاملة

2. ComplianceManager - التحقق من الامتثال
   - GDPR (الخصوصية الأوروبية)
   - HIPAA (بيانات صحية)
   - SOX (الشركات العامة)
   - PCI-DSS (بيانات بطاقات الائتمان)
   - ISO-27001 (أمان المعلومات)

الدوال الرئيسية:
- log_event() - تسجيل حدث
- get_events() - البحث والتصفية
- generate_compliance_report() - تقرير الامتثال
"""
```

**مثال الاستخدام**:
```python
# تسجيل حدث
await audit_mgr.log_event(
    event_type="resource_access",
    agent_id="agent-001",
    action="read_database",
    details="Accessed customer data",
    status="success"
)

# الحصول على التقرير
report = await compliance_mgr.generate_report(
    framework="gdpr",
    period="monthly"
)
```

---

### `database.py` - قاعدة البيانات
**الهدف**: حفظ البيانات بشكل آمن وموثوق

```python
"""
الجداول الرئيسية:
1. users - المستخدمين
   - اسم المستخدم
   - كلمة المرور (مشفرة!)
   - الدور (admin/user)
   - الحالة (active/suspended)

2. agents - الوكلاء
   - معرّف الوكيل
   - الاسم والنوع
   - الحالة
   - بيانات وصفية

3. events - سجل الأحداث
   - نوع الحدث
   - معرّف الوكيل
   - العملية (action)
   - النتيجة (success/failure)

4. sessions - الجلسات
   - معرّف الجلسة
   - وقت البدء والانتهاء
   - الحالة

5. agent_permissions - الصلاحيات
   - معرّف الوكيل
   - المورد والعملية
   - من منح ومتى

الدوال الرئيسية:
- add_agent() - إضافة وكيل
- log_event() - تسجيل حدث
- get_events() - البحث عن أحداث
- add_permission() - إضافة صلاحية
"""
```

**مثال الاستخدام**:
```python
db = Database()

# إضافة وكيل
db.add_agent(
    agent_id="agent-001",
    name="AI Assistant",
    agent_type="llm"
)

# تسجيل حدث
db.log_event(
    event_type="login",
    agent_id="agent-001",
    action="authentication",
    details="Agent logged in",
    status="success"
)

# البحث
events = db.get_events(agent_id="agent-001", limit=50)
```

---

### `agent_registry.py` - سجل الوكلاء
**الهدف**: تخزين سريع للوكلاء في الذاكرة

```python
"""
المسؤوليات:
✓ تخزين الوكلاء في الذاكرة (سريع جداً)
✓ البحث السريع
✓ المزامنة مع قاعدة البيانات
✓ تحديث بيانات الوكيل

الدوال الرئيسية:
- register() - إضافة وكيل
- get() - الحصول على وكيل
- list_all() - قائمة كل الوكلاء
- unregister() - حذف وكيل
"""
```

---

### `app.py` - لوحة التحكم
**الهدف**: واجهة رسومية سهلة لإدارة النظام

```
المميزات:
✓ تسجيل دخول آمن (Login)
✓ صفحة رئيسية بالإحصائيات
✓ إدارة الوكلاء (إضافة، تعديل، حذف)
✓ إدارة المستخدمين (مسؤول فقط)
✓ عرض سجل الأحداث
✓ الإعدادات

البنية:
- الشريط العلوي (header) - المعلومات والخروج
- القائمة الجانبية (sidebar) - الملاحة
- المحتوى الرئيسي (content) - البيانات
```

---

## 🟠 مجلد `api/` - واجهات البرمجة

### `api/main.py` - REST API
**الهدف**: API تقليدي لتكامل البرامج

```python
"""
نقاط النهاية الرئيسية:
GET    /health              - فحص صحة النظام
POST   /api/agents          - إنشاء وكيل
GET    /api/agents          - قائمة الوكلاء
POST   /api/authenticate    - التحقق
POST   /api/authorize       - فحص الصلاحيات
GET    /api/events          - سجل الأحداث
"""
```

---

### `api/graphql.py` - GraphQL API
**الهدف**: API حديث بمميزات متقدمة

```graphql
"""
الاستعلامات الرئيسية:
- agents - قائمة الوكلاء
- agent(id) - وكيل معين
- events - سجل الأحداث
- permissions - الصلاحيات

الـ Mutations (التعديلات):
- registerAgent - إضافة وكيل
- updateAgent - تعديل وكيل
- deleteAgent - حذف وكيل
"""
```

---

### `api/models.py` - نماذج البيانات
**الهدف**: تعريف هيكل البيانات

```python
"""
النماذج:
- Agent - بيانات الوكيل
- User - بيانات المستخدم
- Event - حدث في السجل
- Session - جلسة الوكيل
- Credential - بيانات الاعتماد
- Permission - الصلاحيات
"""
```

---

## 🟡 مجلد `core/` - النواة

### `core/agentic_iam.py` - محرك النظام الرئيسي
**الهدف**: دمج كل المكونات في نظام واحد

```python
"""
المسؤوليات:
✓ تهيئة كل المكونات
✓ الربط بينها
✓ إدارة دورة الحياة
✓ توفير واجهة موحدة

المكونات المُدارة:
- Authentication Manager
- Authorization Manager
- Session Manager
- Credential Manager
- Federated Identity Manager
- Transport Security Manager
- Audit Manager
- Compliance Manager
- Agent Registry
- Database
"""
```

**مثال الاستخدام**:
```python
from core.agentic_iam import AgenticIAM

iam = AgenticIAM(settings)
await iam.initialize()

# الآن يمكن استخدام جميع المكونات
result = await iam.authentication_manager.authenticate(...)
```

---

## 🟢 مجلد `dashboard/` - الواجهة الرسومية

### `dashboard/components/` - مكونات الواجهة
**الهدف**: عناصر واجهة معاد استخدامها

```
الملفات:
- login.py        - صفحة تسجيل الدخول
- agent_selection.py    - اختيار الوكلاء
- agent_management.py   - إدارة الوكلاء
- user_management.py    - إدارة المستخدمين
- audit_log.py         - سجل الأحداث
- settings.py          - الإعدادات
```

---

## 🔵 مجلد `config/` - الإعدادات

### `config/settings.py` - إعدادات النظام
**الهدف**: التحكم في سلوك النظام

```python
"""
الإعدادات الرئيسية:
- DEBUG - وضع التطوير
- DATABASE_PATH - مسار قاعدة البيانات
- LOG_LEVEL - مستوى التسجيل
- SESSION_TIMEOUT - مدة انتهاء الجلسة
- CREDENTIAL_TTL - صلاحية البيانات
- SSL/TLS - إعدادات التشفير
"""

# الاستخدام:
settings = Settings()
print(settings.DEBUG)
print(settings.DATABASE_PATH)
```

---

## 🟣 مجلد `tests/` - الاختبارات

### `tests/unit/` - اختبارات الوحدات
**الهدف**: اختبار كل مكون بمعزل

```
الملفات:
- test_authentication.py
- test_authorization.py
- test_session_manager.py
- test_credential_manager.py
- test_audit.py
```

---

### `tests/integration/` - اختبارات التكامل
**الهدف**: اختبار المكونات معاً

```
الملفات:
- test_full_flow.py - تدفق كامل
- test_api.py - اختبار API
- test_dashboard.py - اختبار الواجهة
```

---

### `tests/e2e/` - اختبارات النهاية للنهاية
**الهدف**: اختبار من منظور المستخدم

```
الملفات:
- test_user_workflow.py - سيناريو المستخدم
- test_admin_workflow.py - سيناريو المسؤول
```

---

## 🟤 ملفات الإعدادات

### `requirements.txt` - الحزم المطلوبة
```
استخدام:
pip install -r requirements.txt

المحتوى:
- fastapi - إطار API
- pydantic - التحقق من البيانات
- sqlalchemy - قاعدة البيانات
- streamlit - الواجهة الرسومية
- ariadne - GraphQL
- pytest - الاختبارات
```

---

### `pytest.ini` - إعدادات الاختبارات
```ini
[pytest]
# مسارات الاختبارات
testpaths = tests

# معايير التغطية
addopts = --cov=. --cov-report=html

# آسينك
asyncio_mode = auto
```

---

### `.env.example` - متغيرات البيئة
```bash
# نسخ إلى .env وعدّل
cp .env.example .env

# المحتوى:
DEBUG=true
DATABASE_PATH=./data/agentic_iam.db
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here
```

---

### `Dockerfile` - صورة Docker
**الهدف**: تشغيل النظام في حاوية

```dockerfile
# البناء:
docker build -t agentic-iam:latest .

# التشغيل:
docker run -p 8501:8501 agentic-iam:latest
```

---

### `docker-compose.yml` - تشغيل كل المكونات
**الهدف**: تشغيل API والواجهة معاً

```bash
# التشغيل:
docker-compose up

# يبدأ تلقائياً:
- Dashboard على http://localhost:8501
- API على http://localhost:8000
- GraphQL على http://localhost:8000/graphql
```

---

## 📊 خريطة العلاقات

```
┌─────────────────────────────────────────────────────┐
│        Presentation Layer (الواجهات)               │
│  ┌─────────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ app.py          │  │ api/main   │  │GraphQL   │ │
│  │ (Streamlit)     │  │ (REST)     │  │          │ │
│  └─────────────────┘  └────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────┐
│     Business Logic (المنطق والعمليات)              │
│  ┌──────────────────────────────────────────────── │
│  │ core/agentic_iam.py (محرك النظام)              │
│  ├──────────────────────────────────────────────── │
│  │ ├─ authentication.py                            │
│  │ ├─ authorization.py                            │
│  │ ├─ agent_identity.py                           │
│  │ ├─ session_manager.py                          │
│  │ ├─ credential_manager.py                       │
│  │ ├─ federated_identity.py                       │
│  │ ├─ transport_binding.py                        │
│  │ ├─ audit_compliance.py                         │
│  │ └─ agent_registry.py                           │
│  └──────────────────────────────────────────────── │
└─────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────┐
│        Data Layer (قاعدة البيانات)                 │
│  ┌─────────────────╖                                │
│  │ database.py     ║                                │
│  │ (SQLite/Postgres)                               │
│  └─────────────────╜                                │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 كيفية الاستخدام

### لفهم النظام:
1. اقرأ **README.md** - النظرة العامة
2. اقرأ **ARCHITECTURE_DETAILED.md** - البنية المفصلة
3. اقرأ **هذا الملف** - الملفات والمكونات

### لبدء العمل:
1. ثبّت الحزم: `pip install -r requirements.txt`
2. *شغّل* التطبيق: `python run_gui.py`
3. درّب الأمثلة في **CODE_EXAMPLES.md**

### للتطوير:
1. اقرأ كود **core/agentic_iam.py** - الهيكل الأساسي
2. ادرس كود المكونات الفردية
3. اكتب الاختبارات في **tests/**

---

هذا هو دليلك الشامل! 🎉
