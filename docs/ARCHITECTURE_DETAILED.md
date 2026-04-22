# 🏗️ البنية المعمارية المفصلة - Agentic-IAM

## المحتويات

1. [نظرة عامة على الطبقات](#نظرة-عامة-على-الطبقات)
2. [تدفق البيانات](#تدفق-البيانات)
3. [التفاعلات بين المكونات](#التفاعلات-بين-المكونات)
4. [أمثلة عملية](#أمثلة-عملية)

---

## نظرة عامة على الطبقات

### الطبقة الأولى: الواجهات (Presentation Layer)

```
┌─────────────────────────────────────────────┐
│         Presentation Layer                   │
├─────────────────────────────────────────────┤
│  [Streamlit Dashboard] → http://localhost:8501
│  [REST API]            → http://localhost:8000
│  [GraphQL API]         → http://localhost:8000/graphql
└─────────────────────────────────────────────┘
```

#### Streamlit Dashboard (`app.py`)
**الهدف**: واجهة رسومية سهلة الاستخدام للإدارة

**المميزات**:
- 🔐 نظام دخول آمن (Login System)
- 📊 لوحة تحكم تفاعلية
- 👥 إدارة الوكلاء والمستخدمين
- 📋 عرض سجل الأحداث
- ⚙️ إعدادات النظام

**الملفات المرتبطة**:
- `app.py` - التطبيق الرئيسي
- `dashboard/components/` - مكونات الواجهة
- `dashboard/realtime.py` - تحديثات فوري

#### REST API (`api/main.py`)

**الهدف**: API تقليدي لتكامل البرامج

**نقاط النهاية الرئيسية**:
```
GET    /health              - فحص صحة النظام
POST   /api/agents          - إنشاء وكيل جديد
GET    /api/agents          - الحصول على قائمة الوكلاء
GET    /api/agents/{id}     - الحصول على بيانات وكيل
POST   /api/authenticate    - التحقق من الوكيل
POST   /api/authorize       - التحقق من الصلاحيات
GET    /api/events          - سجل الأحداث
```

#### GraphQL API (`api/graphql.py`)

**الهدف**: API حديث بمميزات متقدمة

**الاستعلامات المتاحة**:
```graphql
query {
  agents { id name status }
  events(agentId: "123") { type action status }
  agent(id: "123") { permissions }
}

mutation {
  registerAgent(input: {...}) { id status }
  updateAgentStatus(id: "123", status: "suspended")
}
```

---

### الطبقة الثانية: منطق الأعمال (Business Logic)

```
┌──────────────────────────────────────────────────────────────┐
│                   Business Logic Layer                        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐              │
│  │ Authentication   │◄────►│ Authorization    │              │
│  │ Manager          │      │ Manager          │              │
│  └──────────────────┘      └──────────────────┘              │
│           ▲                         ▲                        │
│           │                         │                        │
│  ┌────────┴─────────────────────────┴──────────┐             │
│  │                                             │             │
│  ▼                                             ▼             │
│  ┌──────────────────┐      ┌──────────────────┐             │
│  │ Session          │      │ Credential       │             │
│  │ Manager          │      │ Manager          │             │
│  └──────────────────┘      └──────────────────┘             │
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐             │
│  │ Federated        │      │ Transport        │             │
│  │ Identity         │      │ Security         │             │
│  │ Manager          │      │ Manager          │             │
│  └──────────────────┘      └──────────────────┘             │
│                                                               │
│  ┌──────────────────────────────────────────┐               │
│  │ Audit & Compliance Manager               │               │
│  └──────────────────────────────────────────┘               │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### 1. Authentication Manager للتحقق من الهوية

**المسؤوليات**:
```python
✓ التحقق من صحة البيانات (مارة الزر)
✓ حساب درجة الثقة
✓ تسجيل محاولات المصادقة
✓ تطبيق حدود المحاولات الفاشلة
```

**التفاصيل**:
- يتحقق من أن البيانات محفوظة بشكل صحيح
- يتحقق من عدم انتهاء صلاحيتها
- يحسب درجة ثقة بناءً على جودة البيانات
- يسجل كل محاولة (ناجحة أو فاشلة)
- يحظر الحساب بعد X محاولات فاشلة

**أمثلة الطرق**:
```python
authenticate(agent_id, credentials, method)
verify_credential(credential)
calculate_trust_level(credential)
is_credential_valid(credential)
```

#### 2. Authorization Manager للتحقق من الصلاحيات

**المسؤوليات**:
```python
✓ التحقق من وجود الصلاحية المطلوبة
✓ تقييم قواعس RBAC و ABAC
✓ التحقق من السياق (الوقت، المكان، إلخ)
✓ تسجيل قرارات التفويض
```

**التفاصيل**:
- يحصل على الأدوار الموكلة للوكيل
- يحصل على الصلاحيات المرتبطة بكل دور
- يقيّم القواعس الإضافية (ABAC)
- يسجل القرار (سماح/رفض)
- يُرسل تنبيهات أمنية عند الرفض

**أمثلة الطرق**:
```python
authorize(agent_id, resource, action, context)
check_permission(agent_id, permission)
get_agent_permissions(agent_id)
get_agent_roles(agent_id)
evaluate_policy(agent_id, policy)
```

#### 3. Session Manager لإدارة الجلسات

**المسؤوليات**:
```python
✓ إنشاء جلسات جديدة
✓ التحقق من صحة الجلسات
✓ إدارة انتهاء صلاحية الجلسة
✓ الكشف عن أنماط مريبة
```

**التفاصيل**:
- ينشئ معرّف جلسة فريد
- يخزن بيانات الجلسة (عنوان IP، الجهاز، إلخ)
- يحدد وقت انتهاء الجلسة
- يكتشف محاولات الاستيلاء على الجلسة
- يسجل أنشطة الجلسة

**أمثلة الطرق**:
```python
create_session(agent_id, metadata)
validate_session(session_id)
end_session(session_id)
get_active_sessions(agent_id)
is_session_suspicious(session_id)
```

#### 4. Credential Manager لإدارة البيانات

**المسؤوليات**:
```python
✓ إنشاء بيانات جديدة
✓ التخزين الآمن (مشفر)
✓ التدوير التلقائي
✓ إبطال البيانات المنتهية
```

**التفاصيل**:
- ينشئ بيانات عشوائية آمنة
- يشفرها قبل الحفظ
- ينسجل معرّف الوكيل لكل بيانات
- يحدد صلاحية كل بيانات
- يدور البيانات تلقائياً بعد وقت معين

**أمثلة الطرق**:
```python
create_credential(agent_id, type, ttl_days)
get_credential(credential_id)
rotate_credential(credential_id)
revoke_credential(credential_id)
list_credentials(agent_id)
```

#### 5. Federated Identity Manager للربط الخارجي

**المسؤوليات**:
```python
✓ الربط مع أنظمة هويات خارجية
✓ المزامنة مع Azure AD، AWS IAM، إلخ
✓ التحقق من التوقيعات
✓ إدارة الثقة بين الأنظمة
```

**التفاصيل**:
- يربط هوية الوكيل المحلية مع هوية خارجية
- يُحالف مع Azure AD، AWS IAM، Okta، إلخ
- يحقق من توقيع الرموز (Tokens)
- يُحدّث الصلاحيات من النظام الخارجي
- يزامن الحذف والتعطيل

**أمثلة الطرق**:
```python
federate_identity(agent_id, provider, external_id)
validate_federated_token(provider, token)
sync_with_external_provider(provider)
update_federated_permissions(agent_id, provider)
```

#### 6. Transport Security Manager لأمان النقل

**المسؤوليات**:
```python
✓ تفعيل mTLS (تشفير متبادل)
✓ التحقق من الشهادات
✓ إدارة مفاتيح التشفير
✓ دعم الخوارزميات الآمنة المستقبلية
```

**التفاصيل**:
- يُفعّل mTLS على كل الاتصالات
- يتحقق من صحة شهادات العميل والخادم
- يدير دورة حياة الشهادات
- يدعم تشفير آمن (TLS 1.3+)
- يسجل مخاطر السلامة

---

### الطبقة الثالثة: البيانات (Data Layer)

```
┌──────────────────────────────────────────────────────────────┐
│                  Data Persistence Layer                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────┐        ┌────────────────┐               │
│  │ SQLite/Postgres│        │ Agent Registry │               │
│  │                │        │ (In-Memory)    │               │
│  │ ┌────────────┐ │        │ ┌──────────┐   │               │
│  │ │ users      │ │        │ │ Agents   │   │               │
│  │ │ agents     │ │        │ │ storage  │   │               │
│  │ │ events     │ │        │ │ metadata │   │               │
│  │ │ sessions   │ │        │ └──────────┘   │               │
│  │ │ permissions│ │        │                │               │
│  │ └────────────┘ │        └────────────────┘               │
│  └────────────────┘                                         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### قاعدة البيانات

**جدول المستخدمين (Users)**:
```sql
id          INTEGER PRIMARY KEY
username    TEXT UNIQUE NOT NULL      -- اسم المستخدم
password_hash BLOB NOT NULL            -- كلمة المرور (مشفرة!)
email       TEXT UNIQUE NOT NULL      -- البريد الإلكتروني
role        TEXT DEFAULT 'user'       -- admin أو user
status      TEXT DEFAULT 'active'     -- active/suspended/inactive
created_at  TIMESTAMP                 -- وقت الإنشاء
last_login  TIMESTAMP                 -- آخر دخول
```

**جدول الوكلاء (Agents)**:
```sql
id          TEXT PRIMARY KEY          -- معرّف الوكيل الفريد
name        TEXT NOT NULL             -- اسم الوكيل
type        TEXT                      -- نوع الوكيل (llm, worker, etc)
status      TEXT DEFAULT 'active'     -- active/suspended/inactive
metadata    TEXT                      -- بيانات إضافية (JSON)
created_at  TIMESTAMP                 -- تاريخ الإنشاء
updated_at  TIMESTAMP                 -- آخر تحديث
```

**جدول الأحداث (Events)**:
```sql
id          INTEGER PRIMARY KEY
event_type  TEXT NOT NULL             -- login, authorization, error
agent_id    TEXT                      -- معرّف الوكيل
action      TEXT                      -- العملية المنفذة
details     TEXT                      -- تفاصيل العملية
status      TEXT DEFAULT 'success'    -- success أو failure
created_at  TIMESTAMP                 -- وقت الحدث
```

**جدول الجلسات (Sessions)**:
```sql
id          TEXT PRIMARY KEY          -- معرّف الجلسة
agent_id    TEXT NOT NULL             -- معرّف الوكيل
started_at  TIMESTAMP                 -- وقت البدء
ended_at    TIMESTAMP                 -- وقت الانتهاء
status      TEXT DEFAULT 'active'     -- active أو ended
metadata    TEXT                      -- بيانات الجلسة (JSON)
```

**جدول الصلاحيات (Permissions)**:
```sql
id          INTEGER PRIMARY KEY
agent_id    TEXT NOT NULL             -- معرّف الوكيل
resource    TEXT NOT NULL             -- المورد (ملف، قاعدة، إلخ)
action      TEXT NOT NULL             -- العملية (read, write, delete)
granted_by  TEXT                      -- من منح الصلاحية
granted_at  TIMESTAMP                 -- وقت المنح
```

#### Agent Registry (ذاكرة في الذاكرة)

**الهدف**: تخزين سريع للوكلاء النشطين

**المميزات**:
- تخزين في الذاكرة (سريع جداً)
- مزامنة مع قاعدة البيانات
- دعم البحث والفلترة السريع

```python
# البنية
registry = {
    "agent-001": {
        "id": "agent-001",
        "name": "AI Assistant",
        "status": "active",
        "metadata": {...}
    }
}
```

---

## تدفق البيانات

### تدفق المصادقة (Authentication Flow)

```
1. الوكيل يرسل طلب
   ├─ معرّف الوكيل
   ├─ البيانات المرسلة
   └─ طريقة التوثيق

2. Authentication Manager يستقبل الطلب
   ├─ يستخرج البيانات من الطلب
   ├─ يتحقق من صحة التوقيع
   ├─ يفك تشفير البيانات
   └─ يحسب درجة الثقة

3. يبحث عن البيانات في قاعدة البيانات
   ├─ هل البيانات موجودة؟
   ├─ هل صلاحيتها سارية؟
   └─ هل تطابق البيانات المرسلة؟

4. إذا كانت صحيحة:
   ├─ ينشئ AuthenticationResult (نجح)
   ├─ يسجل الحدث في البيانات
   └─ يرجع النتيجة

5. إذا كانت خاطئة:
   ├─ ينشئ AuthenticationResult (فشل)
   ├─ يسجل محاولة فاشلة
   ├─ يتحقق من عدد المحاولات
   ├─ إذا تجاوزت الحد: ينعّل الحساب
   └─ يرجع النتيجة
```

### تدفق التفويض (Authorization Flow)

```
1. الوكيل يطلب إجراء على موارد
   ├─ معرّف الوكيل
   ├─ المورد المطلوب
   ├─ العملية المطلوبة
   └─ السياق

2. Authorization Manager يستقبل الطلب
   ├─ يحصل على أدوار الوكيل من البيانات
   ├─ يحصل على الصلاحيات المرتبطة بكل دور
   └─ يحصل على قواعس ABAC

3. يقيّم القواعس
   ├─ يتحقق من البيئة (إنتاج/اختبار)
   ├─ يتحقق من الوقت (ساعات العمل؟)
   ├─ يتحقق من الموقع (معتمد؟)
   └─ يتحقق من مستوى المخاطرة

4. القرار النهائي
   ├─ إذا جميع الشروط صحيحة: اسمح
   ├─ إذا شرط فاشل: ارفض
   └─ يسجل القرار والسبب

5. تسجيل في قاعدة البيانات
   ├─ سجل الحدث (authorize_request)
   ├─ القرار (allow/deny)
   └─ السبب والمعلومات
```

### تدفق إنشاء جلسة (Session Creation Flow)

```
1. بداية جلسة جديدة
   ├─ معرّف الوكيل
   ├─ عنوان IP
   ├─ الجهاز
   └─ معلومات أخرى

2. Session Manager ينشئ جلسة
   ├─ يولّد معرّف جلسة فريد (UUID)
   ├─ يحفظ وقت البدء
   ├─ يخزن هويته وبيانات الجهاز
   └─ يحدد وقت انتهاء الصلاحية (مثلاً 24 ساعة)

3. ينشر الجلسة
   ├─ يحفظها في الذاكرة (سريع)
   ├─ يحفظها في قاعدة البيانات (دائم)
   └─ يرجع معرّف الجلسة

4. استخدام الجلسة
   ├─ الوكيل يرسل الطلبات مع معرّف الجلسة
   ├─ الخادم يتحقق من الجلسة في الذاكرة
   ├─ يتحقق من عدم انتهاء الموعد
   └─ يسمح بالعملية

5. انتهاء الجلسة
   ├─ إذا انتهت الصلاحية تلقائياً
   ├─ أو الوكيل طلب تسجيل خروج
   ├─ يحدّث الحالة في الذاكرة
   ├─ يحدّث الحالة في قاعدة البيانات
   └─ ينظّف الموارد المستخدمة
```

---

## التفاعلات بين المكونات

### سيناريو 1: وكيل يريد قراءة ملف

```
Workflow المكتمل:

1. الوكيل يرسل طلب read على /files/data.json

2. Transport Security Manager
   ├─ يتحقق من شهادة TLS المتبادلة
   ├─ يفك تشفير الرسالة
   └─ يسمح بالمتابعة

3. Authentication Manager
   ├─ يستخرج بيانات الوكيل من الرسالة
   ├─ يتحقق من البيانات
   ├─ ينجح في التحقق
   └─ ينشئ AuthenticationResult(success=True)

4. Session Manager
   ├─ يحصل على معرّف الجلسة من الطلب
   ├─ يتحقق من صحة الجلسة
   ├─ يتحقق من عدم انتهاء الموعد
   └─ ينجح في التحقق

5. Audit Manager
   ├─ يسجل: "agent-001 attempted read /files/data.json"
   └─ الحالة: pending

6. Authorization Manager
   ├─ يحصل على أدوار الوكيل: ["reader"]
   ├─ يحصل على الصلاحيات: ["file:read"]
   ├─ يتحقق من السياق (إنتاج، ساعات العمل، إلخ)
   ├─ جميع الشروط صحيحة
   └─ ينشئ AuthorizationDecision(allow=True)

7. Audit Manager
   ├─ يحدّث السجل: "Authorization: ALLOW"
   └─ يحفظ في قاعدة البيانات

8. تنفيذ العملية
   ├─ اقراءة الملف
   ├─ إرسال المحتوى للوكيل
   └─ تشفيره (TLS)

9. التسجيل النهائي
   ├─ سجل الحدث: status=success
   └─ حفظ في قاعدة البيانات

النتيجة: ✅ الوكيل يحصل على الملف بنجاح
```

### سيناريو 2: وكيل يحاول كتابة ملف بدون صلاحيات

```
Workflow المكتمل:

1-4. النقاط 1-4 نفسها كما في السيناريو الأول

5. Audit Manager
   ├─ يسجل: "agent-001 attempted write /files/data.json"
   └─ الحالة: pending

6. Authorization Manager
   ├─ يحصل على أدوار الوكيل: ["reader"]
   ├─ يحصل على الصلاحيات: ["file:read"] فقط
   ├─ يتحقق من الصلاحية: file:write
   ├─ الصلاحية غير موجودة!
   └─ ينشئ AuthorizationDecision(allow=False, reason="insufficient_permissions")

7. Audit Manager + Security Alert
   ├─ يحدّث السجل: "Authorization: DENY (insufficient permissions)"
   ├─ يسجل تنبيه أمني
   ├─ قد يحظر الوكيل بعد X محاولات
   └─ يحفظ كل شيء في قاعدة البيانات

8. إرسال خطأ للوكيل
   ├─ HTTP 403 Forbidden
   └─ الرسالة: "You don't have permission to write this file"

النتيجة: ❌ الوكيل يحصل على رسالة رفض
+ يتم توثيق محاولة غير مصرح بها
```

---

## أمثلة عملية

### مثال 1: كود كامل للتسجيل والعمل

```python
from core.agentic_iam import AgenticIAM
from config.settings import Settings
import asyncio

async def main():
    # 1. إعداد النظام
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # 2. تسجيل وكيل جديد
    agent = iam.identity_manager.create_identity(
        agent_id="my-ai-assistant",
        metadata={"type": "llm", "version": "2.0"}
    )
    
    # 3. توليد مفاتيح
    agent = AgentIdentity.generate(agent_id="my-ai-assistant")
    print(f"🔐 Public Key: {agent.get_public_key()}")
    
    # 4. حفظ الوكيل في البيانات
    iam.agent_registry.register(agent)
    
    # 5. التحقق من الوكيل
    auth = await iam.authentication_manager.authenticate(
        agent_id="my-ai-assistant",
        credentials={"api_key": "secret"},
        method="api_key"
    )
    
    if auth.success:
        print(f"✅ Authenticated: trust_level={auth.trust_level}")
        
        # 6. بدء جلسة
        session = await iam.session_manager.create_session(
            agent_id="my-ai-assistant",
            metadata={"ip": "192.168.1.1"}
        )
        
        # 7. التحقق من صلاحيات المورد
        decision = await iam.authorization_manager.authorize(
            agent_id="my-ai-assistant",
            resource="database://users",
            action="read"
        )
        
        if decision.allow:
            print("✅ Authorized to read database")
            # إجراء العملية
        else:
            print(f"❌ Not authorized: {decision.reason}")
        
        # 8. تسجيل خروج
        await iam.session_manager.end_session(session.session_id)
        
    else:
        print("❌ Authentication failed")
    
    # 9. إيقاف النظام
    await iam.shutdown()

asyncio.run(main())
```

---

هذا هو الشرح المفصل والكامل للبنية المعمارية! 🎉
