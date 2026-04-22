# ⚡ بدء سريع ونصائح - Agentic-IAM

## 📖 المحتويات

1. [البدء السريع (5 دقائق)](#البدء-السريع-5-دقائق)
2. [أفضل الممارسات](#أفضل-الممارسات)
3. [استكشاف الأخطاء](#استكشاف-الأخطاء)
4. [الأسئلة الشائعة](#الأسئلة-الشائعة)

---

## البدء السريع (5 دقائق)

### الخطوة 1: إعداد البيئة (1 دقيقة)

```bash
# 1. فتح Terminal
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main

# 2. تفعيل البيئة الافتراضية
.\.venv\Scripts\Activate

# 3. التحقق (يجب أن ترى اسم القاعدة النشطة)
# (.venv) C:\Users\Lenovo\Desktop\Agentic-IAM-main>
```

### الخطوة 2: تثبيت الحزم (1 دقيقة)

```bash
pip install -r requirements.txt
```

### الخطوة 3: التشغيل (1 دقيقة)

**الخيار 1: الواجهة الرسومية (الأسهل)**
```bash
python run_gui.py
```

** الخيار 2: API فقط**
```bash
python api/main.py
```

**الخيار 3: كل شيء (Docker)**
```bash
docker-compose up
```

### الخطوة 4: الوصول (2 دقيقة)

```
🌐 الواجهة الرسومية:    http://localhost:8501
🔌 REST API:           http://localhost:8000
🎯 GraphQL:            http://localhost:8000/graphql
```

### الخطوة 5: تسجيل الدخول (1 دقيقة)

| الدور | اسم | كلمة | 
|------|------|------|
| مسؤول | admin | admin123 |
| مستخدم عادي | user | user123 |

---

## أفضل الممارسات

### 1️⃣ الأمان

#### ✅ اتّبع هذا:
```python
# التخزين الآمن للبيانات الحساسة
from secrets import token_urlsafe

# توليد بيانات قوية
secure_key = token_urlsafe(32)

# عدم طباعة البيانات
secret = get_credential(id)
# لا تطبع: print(secret)  ❌
```

#### ❌ تجنب:
```python
# ❌ لا تخزّن البيانات كنص عادي
password = "admin123"

# ❌ لا تضع البيانات في الكود
api_key = "sk-12345678..."

# ❌ لا تُرسل البيانات في السجلات
logger.info(f"User password: {password}")
```

### 2️⃣ الأداء

#### ✅ اتّبع هذا:
```python
# استخدم البحث بقيود
events = db.get_events(
    agent_id="agent-001",
    limit=100,  # حدّد النتائج
    start_date=datetime.now() - timedelta(days=1)  # فترة زمنية
)

# استخدم التخزين المؤقت (Cache)
cached_permissions = await cache.get(f"perms:{agent_id}")
if not cached_permissions:
    perms = await fetch_permissions(agent_id)
    await cache.set(f"perms:{agent_id}", perms, ttl=3600)
```

#### ❌ تجنب:
```python
# ❌ لا تجلب كل البيانات
events = db.get_events()  # ملايين السجلات!

# ❌ لا تُنفّذ نفس الاستعلام مراراً
for agent in agents:
    perms = await fetch_permissions(agent.id)  # ملايين الطلبات!

# ❌ لا تنتظر العمليات في حلقة
for agent in agents:
    await slow_operation(agent)  # بطيء جداً
```

### 3️⃣ معالجة الأخطاء

#### ✅ اتّبع هذا:
```python
try:
    result = await authenticate(agent_id, credentials)
except AuthenticationError as e:
    logger.error(f"Auth failed for {agent_id}: {str(e)}")
    return {"success": False, "reason": "invalid_credentials"}
except DatabaseError as e:
    logger.error(f"Database error: {str(e)}")
    return {"success": False, "reason": "server_error"}
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    return {"success": False, "reason": "unknown_error"}
```

#### ❌ تجنب:
```python
# ❌ لا تتجاهل الأخطاء
result = await authenticate(agent_id, credentials)
if result:
    ...

# ❌ لا تطبع الموارد الخام (raw error)
except Exception as e:
    print(e)

# ❌ لا تعطّل البرنامج
raise Exception("Something went wrong")
```

### 4️⃣ السجلات (Logging)

#### ✅ اتّبع هذا:
```python
import logging

logger = logging.getLogger(__name__)

# معلومات (للعمليات العادية)
logger.info("Agent registered: assistant-001")

# تحذيرات (للحالات المريبة)
logger.warning(f"Failed authentication attempt: {agent_id}")

# أخطاء (للمشاكل الحقيقية)
logger.error(f"Database connection failed: {str(e)}")

# تصحيح (للتطوير فقط)
logger.debug(f"Agent permissions: {permissions}")
```

#### ❌ تجنب:
```python
# ❌ لا تستخدم print
print("Agent registered")

# ❌ لا تسجّل البيانات الحساسة
logger.info(f"Password: {password}")

# ❌ لا تلتقط الأخطاء بدون تسجيل
try:
    ...
except:
    pass  # ❌ الخطأ اختفى!
```

### 5️⃣ اختبار الكود

#### ✅ اتّبع هذا:
```python
import pytest

@pytest.mark.asyncio
async def test_authentication_success():
    """اختبر النجاح"""
    result = await authenticate("agent-001", {"key": "valid"})
    assert result.success == True
    assert result.trust_level > 0.5

@pytest.mark.asyncio
async def test_authentication_failure():
    """اختبر الفشل"""
    result = await authenticate("agent-001", {"key": "invalid"})
    assert result.success == False

@pytest.mark.asyncio
async def test_authorization_denied():
    """اختبر الرفض"""
    decision = await authorize("user-agent", "sensitive-file", "delete")
    assert decision.allow == False
    assert decision.reason == "insufficient_permissions"
```

#### ❌ تجنب:
```python
# ❌ لا تكتب كود بدون اختبارات
def authenticate(...):
    # كود مهم بدون اختبارات! ❌
    ...

# ❌ لا تختبر الحالات السعيدة فقط
# اختبر الأخطاء والحالات الحدية أيضاً
```

### 6️⃣ التعليقات في الكود

#### ✅ اتّبع هذا:
```python
async def rotate_credential(credential_id: str) -> Credential:
    """
    تدوير بيانات الاعتماد.
    
    يقوم بـ:
    1. التحقق من البيانات الحالية
    2. إنشاء بيانات جديدة
    3. إبطال البيانات القديمة
    
    Args:
        credential_id: معرّف البيانات المطلوب تدويرها
    
    Returns:
        البيانات الجديدة
    
    Raises:
        CredentialNotFoundError: إذا لم تُعثر على البيانات
    """
    # الخطوة 1: التحقق من وجود البيانات
    old_cred = await self.get_credential(credential_id)
    if not old_cred:
        raise CredentialNotFoundError(f"Credential {credential_id} not found")
    
    # الخطوة 2: إنشاء بيانات جديدة
    new_cred = await self.create_credential(
        agent_id=old_cred.agent_id,
        credential_type=old_cred.type,
        ttl_days=old_cred.ttl_days
    )
    
    # الخطوة 3: إبطال البيانات القديمة
    await self.revoke_credential(credential_id)
    
    return new_cred
```

#### ❌ تجنب:
```python
# ❌ لا تكتب كود غامض
async def rc(cid):
    x = await g(cid)  # ماذا هذا؟
    y = await c(x.aid, ...)  # لا أفهم!
    await rv(cid)
    return y

# ❌ لا تكتب تعليقات واضحة من الاسم
# ❌ لا تستخدم أسماء غامضة
```

---

## استكشاف الأخطاء

### المشكلة #1: خطأ الحزم

**الخطأ**:
```
ModuleNotFoundError: No module named 'fastapi'
```

**الحل**:
```bash
# تأكد من تفعيل البيئة الافتراضية
.\.venv\Scripts\Activate

# أعِد تثبيت الحزم
pip install -r requirements.txt --force-reinstall
```

---

### المشكلة #2: قاعدة البيانات مفقودة

**الخطأ**:
```
sqlite3.OperationalError: unable to open database file
```

**الحل**:
```bash
# أنشئ مجلد البيانات
mkdir data

# أعِد تشغيل التطبيق
python run_gui.py
```

---

### المشكلة #3: المنفذ مشغول

**الخطأ**:
```
OSError: [Errno 48] Address already in use
```

**الحل**:
```bash
# الخيار 1: أغلق التطبيق السابق
# قاتل العملية (Windows)
taskkill /PID process_id /F

# قاتل العملية (Linux/Mac)
kill -9 process_id

# الخيار 2: استخدم منفذ مختلف
streamlit run app.py --server.port 8502
```

---

### المشكلة #4: بطء الاستجابة

**السبب**: البيانات كثيرة جداً

**الحل**:
```python
# استخدم حدود البحث
events = db.get_events(
    agent_id="agent-001",
    limit=100,  # ← حدّد النتائج
    start_date=datetime.now() - timedelta(days=7)  # ← حدّد الفترة
)
```

---

### المشكلة #5: استهلاك الذاكرة

**السبب**: الجلسات الميتة لم تُنظّف

**الحل**:
```python
# أضِف مهمة تنظيف دورية
async def cleanup_dead_sessions():
    """تنظيف الجلسات المنتهية"""
    dead_sessions = await session_manager.get_expired_sessions()
    
    for session in dead_sessions:
        await session_manager.end_session(session.session_id)
    
    logger.info(f"Cleaned up {len(dead_sessions)} sessions")

# اجعلها تعمل كل ساعة
schedule.every(1).hours.do(cleanup_dead_sessions)
```

---

## الأسئلة الشائعة

### س: كيف أغيّر كلمة مرور المستخدم؟

**ج**: من لوحة التحكم → إدارة المستخدمين → تعديل المستخدم → تغيير الكلمة

أو برمجياً:
```python
db = Database()
db.change_password(
    username="admin",
    new_password="new-password-123"
)
```

---

### س: هل يمكن استخدام قاعدة بيانات أخرى بدلاً من SQLite؟

**ج**: نعم! عدّل `database.py`:

```python
# بدلاً من SQLite
# استخدم PostgreSQL
import psycopg2

connection_string = "postgresql://user:pass@localhost/db"
conn = psycopg2.connect(connection_string)
```

---

### س: كيف أُضيف وكيل جديد برمجياً؟

**ج**:
```python
from core.agentic_iam import AgenticIAM

iam = AgenticIAM(settings)
await iam.initialize()

# إضافة وكيل
identity = AgentIdentity.generate("new-agent")
iam.agent_registry.register(identity)

await iam.shutdown()
```

---

### س: كيف أحصل على التقارير المراقبة؟

**ج**:
```python
from datetime import datetime, timedelta

# تقرير الأسبوع
report = iam.compliance_manager.generate_report(
    framework="gdpr",
    start_date=datetime.now() - timedelta(days=7),
    end_date=datetime.now()
)

# حفظ التقرير
with open("report.html", "w") as f:
    f.write(report.as_html())
```

---

### س: كيف أُفعّل chaining Authentication؟

**ج**: للتحقق من بيانات متعددة:

```python
# التحقق متعدد المستويات
result1 = await auth.authenticate(agent, creds1, "api_key")
if result1.success:
    result2 = await auth.authenticate(agent, creds2, "mtls")
    if result2.success:
        print("✅ تم التحقق من مستويات متعددة")
```

---

### س: كيف أُراقب الأداء؟

**ج**: استخدم السجلات والمقاييس:

```python
import time

start = time.time()
result = await authenticate(agent, credentials)
duration = time.time() - start

# سجّل المدة
logger.info(f"Authentication took {duration:.2f}s")

# إذا كانت أبطأ من المتوقع
if duration > 0.1:
    logger.warning(f"Slow authentication: {duration:.2f}s")
```

---

### س: كيف أُدعّم اللغات الأخرى؟

**ج**: في الواجهة الرسومية:

```python
# أضِف ملف ترجمة
translations = {
    "ar": {
        "home": "الرئيسية",
        "agents": "الوكلاء",
        "logout": "تسجيل خروج"
    },
    "en": {
        "home": "Home",
        "agents": "Agents",
        "logout": "Logout"
    }
}

# استخدم اللغة المختارة
st.write(translations[language]["home"])
```

---

### س: كيف أحفظ ونسترجع النسخ الاحتياطية؟

**ج**:
```python
import shutil
from datetime import datetime

# حفظ نسخة احتياطية
backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
shutil.copy("data/agentic_iam.db", f"backups/{backup_name}")

# استرجاع من نسخة احتياطية
shutil.copy(f"backups/{backup_name}", "data/agentic_iam.db")

# جدولة النسخ الاحتياطية
schedule.every().day.at("02:00").do(backup_database)
```

---

### س: كيف أُضيف إخطارات عند حالات أمنية؟

**ج**:
```python
async def send_security_alert(event_type, details):
    """إرسال تنبيه أمني"""
    
    # عبر البريد الإلكتروني
    send_email(
        to="admin@example.com",
        subject=f"🚨 تنبيه أمني: {event_type}",
        body=details
    )
    
    # عبر Slack
    send_slack_notification(
        channel="#security",
        message=f"⚠️ {event_type}: {details}"
    )
    
    # عبر SMS
    send_sms(
        phone="+201234567890",
        message=f"⚠️ {event_type}"
    )

# استخدام
if unauthorized_access_attempt:
    await send_security_alert(
        "UNAUTHORIZED_ACCESS_ATTEMPT",
        f"Agent {agent_id} tried to access {resource}"
    )
```

---

### س: هل هناك حد أقصى لعدد الوكلاء؟

**ج**: لا، لكن الأداء تتأثر:
- SQLite: ~100,000 وكيل
- PostgreSQL: ملايين الوكلاء

زيادة الأداء:
```python
# أضِف فهارس (indexes)
db.execute("""
    CREATE INDEX idx_agents_status ON agents(status);
    CREATE INDEX idx_events_agent_id ON events(agent_id);
""")

# استخدم PostgreSQL بدلاً من SQLite
```

---

هذا هو الدليل الشامل والكامل! 🚀

لأي أسئلة أخرى، راجع **ARCHITECTURE_DETAILED.md** و **CODE_EXAMPLES.md**

