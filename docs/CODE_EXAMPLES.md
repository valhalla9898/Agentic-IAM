# 💻 أمثلة عملية على الاستخدام - Agentic-IAM

## قائمة الأمثلة

1. [تسجيل وكيل جديد](#-تسجيل-وكيل-جديد)
2. [التحقق من بيانات الوكيل](#-التحقق-من-بيانات-الوكيل)
3. [التحقق من الصلاحيات](#-التحقق-من-الصلاحيات)
4. [إدارة الجلسات](#-إدارة-الجلسات)
5. [إدارة البيانات](#-إدارة-البيانات)
6. [الربط مع أنظمة خارجية](#-الربط-مع-أنظمة-خارجية)
7. [سجل الأحداث](#-سجل-الأحداث)
8. [REST API](#-rest-api)
9. [GraphQL API](#-graphql-api)

---

## 1️⃣ تسجيل وكيل جديد

### الطريقة الأساسية

```python
from core.agentic_iam import AgenticIAM
from config.settings import Settings
from agent_identity import AgentIdentity
import asyncio

async def register_new_agent():
    """تسجيل وكيل جديد في النظام"""
    
    # إعداد النظام
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # ✅ الخطوة 1: إنشاء هوية الوكيل
    agent_identity = AgentIdentity.generate(
        agent_id="assistant-001",
        metadata={
            "name": "AI Assistant",
            "type": "llm",
            "version": "2.0",
            "environment": "production"
        }
    )
    
    # ✅ الخطوة 2: تسجيل الوكيل
    iam.agent_registry.register(agent_identity)
    
    # ✅ الخطوة 3: حفظ الوكيل في قاعدة البيانات
    db = iam.database
    db.add_agent(
        agent_id="assistant-001",
        name="AI Assistant",
        agent_type="llm",
        metadata=agent_identity.to_dict()
    )
    
    # ✅ الخطوة 4: إنشاء بيانات اعتماد
    credential = await iam.credential_manager.create_credential(
        agent_id="assistant-001",
        credential_type="api_key",
        ttl_days=365  # صلاحية سنة واحدة
    )
    
    print(f"""
    ✅ تم تسجيل الوكيل بنجاح!
    
    معرّف الوكيل: assistant-001
    المفتاح العام: {agent_identity.get_public_key()[:50]}...
    معرّف البيانات: {credential.credential_id}
    
    ⚠️ احفظ المفتاح الخاص في مكان آمن:
    {agent_identity.get_private_key()[:50]}...
    """)
    
    await iam.shutdown()

# التشغيل
asyncio.run(register_new_agent())
```

### تسجيل عدة وكلاء دفعة واحدة

```python
async def register_batch_agents():
    """تسجيل عدة وكلاء في نفس الوقت"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # قائمة الوكلاء للتسجيل
    agents_data = [
        {"id": "data-processor-1", "name": "Data Processor", "type": "worker"},
        {"id": "data-processor-2", "name": "Data Processor 2", "type": "worker"},
        {"id": "ml-model-1", "name": "ML Model", "type": "ml_model"},
        {"id": "api-gateway-1", "name": "API Gateway", "type": "gateway"},
    ]
    
    registered_agents = []
    
    for agent_data in agents_data:
        # إنشاء هوية
        identity = AgentIdentity.generate(
            agent_id=agent_data["id"],
            metadata={
                "name": agent_data["name"],
                "type": agent_data["type"]
            }
        )
        
        # تسجيل
        iam.agent_registry.register(identity)
        
        # حفظ في البيانات
        iam.database.add_agent(
            agent_id=agent_data["id"],
            name=agent_data["name"],
            agent_type=agent_data["type"]
        )
        
        registered_agents.append(agent_data["id"])
        print(f"✅ تم تسجيل: {agent_data['name']}")
    
    print(f"\nتم تسجيل {len(registered_agents)} وكلاء بنجاح")
    
    await iam.shutdown()

asyncio.run(register_batch_agents())
```

---

## 2️⃣ التحقق من بيانات الوكيل

### التحقق البسيط

```python
async def authenticate_agent():
    """التحقق من بيانات وكيل"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # بيانات الوكيل
    agent_id = "assistant-001"
    api_key = "your-secret-api-key-here"
    
    # ✅ التحقق
    result = await iam.authentication_manager.authenticate(
        agent_id=agent_id,
        credentials={"api_key": api_key},
        method="api_key"
    )
    
    # الحصول على النتيجة
    if result.success:
        print(f"""
        ✅ تم التحقق بنجاح!
        
        معرّف الوكيل: {result.agent_id}
        طريقة التحقق: {result.auth_method}
        درجة الثقة: {result.trust_level * 100:.1f}%
        """)
    else:
        print(f"❌ فشل التحقق: {result.auth_method}")
    
    await iam.shutdown()

asyncio.run(authenticate_agent())
```

### التحقق المتقدم (mTLS)

```python
async def authenticate_with_mtls():
    """التحقق باستخدام شهادات TLS متبادلة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # شهادة الوكيل
    client_cert = """-----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAJC1/iNAZwqDMA0GCSqGSIb3DQEBBQUAMEUxCzAJ
    ...
    -----END CERTIFICATE-----"""
    
    # بيانات المصادقة
    credentials = {
        "cert": client_cert,
        "key": "...private-key...",
        "ca_cert": "...ca-certificate..."
    }
    
    # التحقق
    result = await iam.authentication_manager.authenticate(
        agent_id="assistant-001",
        credentials=credentials,
        method="mtls"
    )
    
    if result.success:
        print(f"✅ تم التحقق عبر mTLS - درجة الثقة: {result.trust_level}")
    
    await iam.shutdown()

asyncio.run(authenticate_with_mtls())
```

### معالجة أخطاء المصادقة

```python
async def handle_auth_errors():
    """معالجة أخطاء المصادقة المختلفة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # محاولات مختلفة
    test_cases = [
        {
            "agent_id": "assistant-001",
            "credentials": {"api_key": "wrong-key"},
            "name": "مفتاح خاطئ"
        },
        {
            "agent_id": "nonexistent-agent",
            "credentials": {"api_key": "key"},
            "name": "وكيل غير موجود"
        },
        {
            "agent_id": "assistant-001",
            "credentials": {"api_key": "expired-key"},
            "name": "مفتاح منتهي الصلاحية"
        }
    ]
    
    for test in test_cases:
        result = await iam.authentication_manager.authenticate(
            agent_id=test["agent_id"],
            credentials=test["credentials"],
            method="api_key"
        )
        
        if result.success:
            print(f"✅ {test['name']}: نجح")
        else:
            print(f"❌ {test['name']}: فشل")
            # تسجيل في سجل الأحداث
            iam.database.log_event(
                event_type="authentication_failed",
                agent_id=test["agent_id"],
                action="authenticate",
                details=f"Reason: {test['name']}",
                status="failure"
            )
    
    await iam.shutdown()

asyncio.run(handle_auth_errors())
```

---

## 3️⃣ التحقق من الصلاحيات

### التحقق البسيط

```python
async def check_permissions():
    """التحقق من صلاحيات الوكيل"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    agent_id = "assistant-001"
    
    # ✅ التحقق من صلاحية واحدة
    decision = await iam.authorization_manager.authorize(
        agent_id=agent_id,
        resource="database://users",
        action="read"
    )
    
    if decision.allow:
        print("✅ مسموح: قراءة جدول المستخدمين")
    else:
        print(f"❌ ممنوع: {decision.reason}")
    
    # ✅ التحقق من عدة صلاحيات
    operations = [
        ("database://users", "read"),
        ("database://users", "write"),
        ("database://users", "delete"),
        ("api://endpoint", "call"),
        ("file://config", "read"),
    ]
    
    print("\n📋 تقرير الصلاحيات:")
    print("-" * 50)
    
    for resource, action in operations:
        decision = await iam.authorization_manager.authorize(
            agent_id=agent_id,
            resource=resource,
            action=action
        )
        
        status = "✅ مسموح" if decision.allow else "❌ ممنوع"
        print(f"{status:15} {resource:30} {action}")
    
    await iam.shutdown()

asyncio.run(check_permissions())
```

### التحقق المتقدم مع السياق

```python
async def check_with_context():
    """التحقق من الصلاحيات مع السياق"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    from datetime import datetime
    
    # السياق: بيئة الإنتاج، خارج ساعات العمل
    context = {
        "environment": "production",
        "time": datetime.now(),
        "ip_address": "192.168.1.100",
        "region": "us-west-2",
        "risk_level": "low"
    }
    
    # التحقق مع السياق
    decision = await iam.authorization_manager.authorize(
        agent_id="assistant-001",
        resource="database://sensitive_data",
        action="write",
        context=context
    )
    
    if decision.allow:
        print("✅ مسموح في هذا السياق")
    else:
        print(f"❌ ممنوع: {decision.reason}")
        
        # مثلاً قد يكون السبب:
        # - "Outside working hours" (خارج ساعات العمل)
        # - "High risk detection" (اكتشاف خطر عالي)
        # - "Unauthorized region" (منطقة غير مصرح بها)
    
    await iam.shutdown()

asyncio.run(check_with_context())
```

### التحقق مع البيانات الوصفية (ABAC)

```python
async def check_attributes():
    """التحقق من الصلاحيات بناءً على الصفات"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # صفات الوكيل
    agent_attributes = {
        "department": "finance",
        "clearance_level": "level_3",
        "data_agreement": "gdpr_compliant",
        "region": "eu"
    }
    
    # طلب الوصول مع الصفات
    decision = await iam.authorization_manager.authorize(
        agent_id="assistant-001",
        resource="database://eu_customers",
        action="read",
        context={
            "attributes": agent_attributes,
            "request_reason": "reporting"
        }
    )
    
    print(f"القرار: {'✅ مسموح' if decision.allow else '❌ ممنوع'}")
    
    await iam.shutdown()

asyncio.run(check_attributes())
```

---

## 4️⃣ إدارة الجلسات

### إنشاء جلسة

```python
async def create_session():
    """بدء جلسة جديدة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # ✅ بدء جلسة جديدة
    session = await iam.session_manager.create_session(
        agent_id="assistant-001",
        metadata={
            "ip": "192.168.1.100",
            "device": "pod-1",
            "region": "us-west-2",
            "user_agent": "AI-Agent/1.0"
        }
    )
    
    print(f"""
    ✅ تم إنشاء جلسة جديدة!
    
    معرّف الجلسة: {session.session_id}
    معرّف الوكيل: {session.agent_id}
    وقت البدء: {session.started_at}
    وقت الانتهاء المتوقع: {session.expected_end_time}
    """)
    
    await iam.shutdown()

asyncio.run(create_session())
```

### التحقق من صحة الجلسة

```python
async def validate_session():
    """التحقق من صحة الجلسة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    session_id = "session-12345"
    
    # التحقق
    is_valid = await iam.session_manager.validate_session(session_id)
    
    if is_valid:
        print("✅ الجلسة صحيحة ونشطة")
    else:
        print("❌ الجلسة غير صحيحة أو انتهت")
    
    # الحصول على بيانات الجلسة
    session_data = await iam.session_manager.get_session(session_id)
    
    if session_data:
        print(f"""
        معرّف الوكيل: {session_data.agent_id}
        الحالة: {session_data.status}
        مدة الجلسة: {session_data.duration}
        """)
    
    await iam.shutdown()

asyncio.run(validate_session())
```

### إدارة دورة حياة الجلسة

```python
async def manage_session_lifecycle():
    """إدارة دورة حياة الجلسة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # 1. بدء جلسة
    print("1️⃣ بدء جلسة جديدة...")
    session = await iam.session_manager.create_session(
        agent_id="assistant-001"
    )
    session_id = session.session_id
    print(f"   ✅ معرّف الجلسة: {session_id}")
    
    # 2. التحقق من الجلسة
    print("2️⃣ التحقق من صحة الجلسة...")
    is_valid = await iam.session_manager.validate_session(session_id)
    print(f"   {'✅ صحيحة' if is_valid else '❌ خاطئة'}")
    
    # 3. تجديد الجلسة
    print("3️⃣ تجديد الجلسة...")
    renewed_session = await iam.session_manager.renew_session(session_id)
    print(f"   ✅ تم التجديد - موعد انتهاء جديد: {renewed_session.expected_end_time}")
    
    # 4. إنهاء الجلسة
    print("4️⃣ إنهاء الجلسة...")
    await iam.session_manager.end_session(session_id)
    print(f"   ✅ تم الإنهاء")
    
    # 5. التحقق من انتهاء الجلسة
    print("5️⃣ التحقق من انتهاء الجلسة...")
    is_valid = await iam.session_manager.validate_session(session_id)
    print(f"   {'✅ منتهية' if not is_valid else '❌ لا تزال نشطة (مشكلة!)'}")
    
    await iam.shutdown()

asyncio.run(manage_session_lifecycle())
```

---

## 5️⃣ إدارة البيانات

### إنشاء بيانات جديدة

```python
async def create_credentials():
    """إنشاء بيانات جديدة للوكيل"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    agent_id = "assistant-001"
    
    # ✅ إنشاء API Key
    print("إنشاء API Key...")
    api_key = await iam.credential_manager.create_credential(
        agent_id=agent_id,
        credential_type="api_key",
        ttl_days=90
    )
    print(f"✅ تم الإنشاء: {api_key.credential_id}")
    
    # ✅ إنشاء Token
    print("إنشاء Bearer Token...")
    token = await iam.credential_manager.create_credential(
        agent_id=agent_id,
        credential_type="bearer_token",
        ttl_days=7  # صلاحية أسبوع
    )
    print(f"✅ تم الإنشاء: {token.credential_id}")
    
    # ✅ إنشاء شهادة
    print("إنشاء شهادة TLS...")
    cert = await iam.credential_manager.create_credential(
        agent_id=agent_id,
        credential_type="certificate",
        ttl_days=365
    )
    print(f"✅ تم الإنشاء: {cert.credential_id}")
    
    await iam.shutdown()

asyncio.run(create_credentials())
```

### تدوير البيانات

```python
async def rotate_credentials():
    """تدوير البيانات (إنشاء جديدة وإبطال القديمة)"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    agent_id = "assistant-001"
    
    # الحصول على البيانات الحالية
    print("الحصول على البيانات الحالية...")
    old_cred = await iam.credential_manager.get_active_credential(
        agent_id=agent_id,
        credential_type="api_key"
    )
    print(f"البيانات الحالية: {old_cred.credential_id}")
    
    # التدوير
    print("تدوير البيانات...")
    new_cred = await iam.credential_manager.rotate_credential(
        credential_id=old_cred.credential_id
    )
    print(f"✅ البيانات الجديدة: {new_cred.credential_id}")
    print(f"❌ البيانات القديمة أُبطلت")
    
    # التحقق
    print("\nالتحقق من البيانات:")
    old_valid = await iam.credential_manager.is_credential_valid(old_cred.credential_id)
    new_valid = await iam.credential_manager.is_credential_valid(new_cred.credential_id)
    
    print(f"البيانات القديمة صحيحة: {'✅' if old_valid else '❌'}")
    print(f"البيانات الجديدة صحيحة: {'✅' if new_valid else '❌'}")
    
    await iam.shutdown()

asyncio.run(rotate_credentials())
```

### إبطال البيانات

```python
async def revoke_credentials():
    """إبطال بيانات معينة"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    credential_id = "cred-12345"
    
    print(f"إبطال البيانات: {credential_id}")
    
    # التحقق قبل الإبطال
    is_valid = await iam.credential_manager.is_credential_valid(credential_id)
    print(f"قبل الإبطال - صحيحة: {'✅' if is_valid else '❌'}")
    
    # الإبطال
    await iam.credential_manager.revoke_credential(credential_id)
    print("✅ تم الإبطال")
    
    # التحقق بعد الإبطال
    is_valid = await iam.credential_manager.is_credential_valid(credential_id)
    print(f"بعد الإبطال - صحيحة: {'✅' if is_valid else '❌'}")
    
    # تسجيل الحدث
    iam.database.log_event(
        event_type="credential_revoked",
        agent_id="assistant-001",
        action="revoke",
        details=f"Credential {credential_id} revoked",
        status="success"
    )
    
    await iam.shutdown()

asyncio.run(revoke_credentials())
```

---

## 6️⃣ الربط مع أنظمة خارجية

### الربط مع Azure AD

```python
async def federate_with_azure():
    """ربط وكيل محلي مع Azure AD"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    # معرّف الوكيل المحلي
    local_agent_id = "assistant-001"
    
    # معرّف الهوية في Azure
    azure_object_id = "00000000-0000-0000-0000-000000000000"
    
    # الربط
    print("جاري الربط مع Azure AD...")
    identity = await iam.federated_manager.federate_identity(
        agent_id=local_agent_id,
        provider="azure_ad",
        external_id=azure_object_id
    )
    
    print(f"""
    ✅ تم الربط بنجاح!
    
    الهوية المحلية: {identity.agent_id}
    المزود الخارجي: azure_ad
    المعرّف الخارجي: {azure_object_id}
    """)
    
    # التحقق
    print("التحقق من الهوية الموحدة...")
    federated = await iam.federated_manager.get_federated_identity(
        agent_id=local_agent_id
    )
    print(f"✅ الهوية موحدة مع: {federated.provider}")
    
    await iam.shutdown()

asyncio.run(federate_with_azure())
```

### المزامنة مع النظام الخارجي

```python
async def sync_permissions():
    """مزامنة الصلاحيات من النظام الخارجي"""
    
    settings = Settings()
    iam = AgenticIAM(settings)
    await iam.initialize()
    
    agent_id = "assistant-001"
    provider = "azure_ad"
    
    print(f"جاري المزامنة من {provider}...")
    
    # المزامنة
    updated_permissions = await iam.federated_manager.sync_permissions(
        agent_id=agent_id,
        provider=provider
    )
    
    print(f"✅ تم تحديث {len(updated_permissions)} صلاحية")
    
    for perm in updated_permissions:
        print(f"   • {perm.resource} - {perm.action}")
    
    await iam.shutdown()

asyncio.run(sync_permissions())
```

---

## 7️⃣ سجل الأحداث

### تسجيل حدث

```python
def log_event():
    """تسجيل حدث في السجل"""
    
    settings = Settings()
    db = Database()
    
    # تسجيل حدث نجاح
    print("تسجيل حدث نجاح...")
    db.log_event(
        event_type="agent_authorization_granted",
        agent_id="assistant-001",
        action="read_database",
        details="Agent successfully read customer database",
        status="success"
    )
    print("✅ تم التسجيل")
    
    # تسجيل حدث فشل
    print("تسجيل حدث فشل...")
    db.log_event(
        event_type="agent_authorization_denied",
        agent_id="suspicious-agent",
        action="delete_all_data",
        details="Attempted to delete all data from production database",
        status="failure"
    )
    print("✅ تم التسجيل!")

log_event()
```

### البحث في السجل

```python
def search_events():
    """البحث والتصفية في سجل الأحداث"""
    
    db = Database()
    
    # ✅ البحث حسب الوكيل
    print("البحث عن أحداث وكيل معين...")
    events = db.get_events(agent_id="assistant-001", limit=50)
    print(f"وجدت {len(events)} حدث")
    
    # ✅ البحث حسب النوع
    print("البحث عن أحداث فشل المصادقة...")
    failed_auth = db.get_events(
        event_type="authentication_failed",
        limit=20
    )
    print(f"وجدت {len(failed_auth)} محاولة فشل")
    
    # ✅ البحث حسب التاريخ
    from datetime import datetime, timedelta
    yesterday = datetime.now() - timedelta(days=1)
    
    print("البحث عن الأحداث في آخر 24 ساعة...")
    recent = db.get_events(start_date=yesterday, limit=100)
    print(f"وجدت {len(recent)} حدث")
    
    # ✅ طباعة النتائج
    print("\n📋 النتائج:")
    for event in events[:5]:
        print(f"  {event['event_type']:30} {event['agent_id']:20} {event['status']}")

search_events()
```

### إنشاء تقرير

```python
def generate_report():
    """إنشاء تقرير من السجل"""
    
    db = Database()
    
    # الحصول على البيانات
    all_events = db.get_events(limit=1000)
    
    # تجميع الإحصائيات
    stats = {
        "total_events": len(all_events),
        "successful": len([e for e in all_events if e['status'] == 'success']),
        "failed": len([e for e in all_events if e['status'] == 'failure']),
        "event_types": {}
    }
    
    for event in all_events:
        event_type = event['event_type']
        stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
    
    # طباعة التقرير
    print("""
    ╔════════════════════════════════════════╗
    ║        تقرير الأحداث والسجلات          ║
    ╚════════════════════════════════════════╝
    """)
    
    print(f"إجمالي الأحداث:      {stats['total_events']}")
    print(f"الأحداث الناجحة:     {stats['successful']} ✅")
    print(f"الأحداث الفاشلة:     {stats['failed']} ❌")
    
    print("\nتوزيع الأحداث حسب النوع:")
    for event_type, count in stats['event_types'].items():
        percentage = (count / stats['total_events']) * 100
        print(f"  {event_type:30} {count:5d} ({percentage:5.1f}%)")

generate_report()
```

---

## 8️⃣ REST API

### استخدام مع requests

```python
import requests
import json

BASE_URL = "http://localhost:8000"

def rest_api_examples():
    """أمثلة على استخدام REST API"""
    
    # ✅ فحص صحة النظام
    print("1️⃣ فحص صحة النظام...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"الحالة: {response.status_code}")
    print(response.json())
    
    # ✅ تسجيل وكيل جديد
    print("\n2️⃣ تسجيل وكيل جديد...")
    agent_data = {
        "agent_id": "new-agent-001",
        "name": "New AI Agent",
        "type": "llm"
    }
    response = requests.post(
        f"{BASE_URL}/api/agents",
        json=agent_data
    )
    print(f"الحالة: {response.status_code}")
    print(response.json())
    
    # ✅ الحصول على قائمة الوكلاء
    print("\n3️⃣ الحصول على قائمة الوكلاء...")
    response = requests.get(f"{BASE_URL}/api/agents")
    agents = response.json()
    print(f"عدد الوكلاء: {len(agents)}")
    for agent in agents[:3]:
        print(f"  • {agent['id']} - {agent['name']}")
    
    # ✅ التحقق من الوكيل
    print("\n4️⃣ التحقق من الوكيل...")
    auth_data = {
        "agent_id": "new-agent-001",
        "credentials": {"api_key": "secret-key"},
        "method": "api_key"
    }
    response = requests.post(
        f"{BASE_URL}/api/authenticate",
        json=auth_data
    )
    result = response.json()
    print(f"التحقق: {'✅' if result['success'] else '❌'}")
    
    # ✅ التحقق من الصلاحيات
    print("\n5️⃣ التحقق من الصلاحيات...")
    auth_data = {
        "agent_id": "new-agent-001",
        "resource": "database://users",
        "action": "read"
    }
    response = requests.post(
        f"{BASE_URL}/api/authorize",
        json=auth_data
    )
    decision = response.json()
    print(f"القرار: {'✅ مسموح' if decision['allow'] else '❌ ممنوع'}")
    
    # ✅ الحصول على سجل الأحداث
    print("\n6️⃣ الحصول على سجل الأحداث...")
    response = requests.get(
        f"{BASE_URL}/api/events",
        params={"agent_id": "new-agent-001", "limit": 10}
    )
    events = response.json()
    print(f"عدد الأحداث: {len(events)}")
    for event in events[:3]:
        print(f"  • {event['event_type']} - {event['status']}")

rest_api_examples()
```

---

## 9️⃣ GraphQL API

### استخدام مع Python

```python
import requests

BASE_URL = "http://localhost:8000/graphql"

def graphql_examples():
    """أمثلة على استخدام GraphQL API"""
    
    # ✅ الاستعلام عن الوكلاء
    print("1️⃣ الحصول على قائمة الوكلاء...")
    query = """
    query {
        agents {
            id
            name
            status
            createdAt
        }
    }
    """
    
    response = requests.post(
        BASE_URL,
        json={"query": query}
    )
    data = response.json()
    for agent in data['data']['agents']:
        print(f"  • {agent['id']} - {agent['name']} ({agent['status']})")
    
    # ✅ الحصول على بيانات وكيل معين
    print("\n2️⃣ الحصول على بيانات وكيل معين...")
    query = """
    query {
        agent(id: "assistant-001") {
            id
            name
            permissions {
                resource
                action
            }
        }
    }
    """
    
    response = requests.post(
        BASE_URL,
        json={"query": query}
    )
    agent = response.json()['data']['agent']
    print(f"الوكيل: {agent['name']}")
    print("الصلاحيات:")
    for perm in agent['permissions']:
        print(f"  • {perm['resource']} - {perm['action']}")
    
    # ✅ تسجيل وكيل جديد (Mutation)
    print("\n3️⃣ تسجيل وكيل جديد...")
    mutation = """
    mutation {
        registerAgent(input: {
            id: "graphql-agent-001"
            name: "GraphQL Test Agent"
            type: "llm"
        }) {
            id
            name
            status
        }
    }
    """
    
    response = requests.post(
        BASE_URL,
        json={"query": mutation}
    )
    result = response.json()['data']['registerAgent']
    print(f"✅ تم التسجيل: {result['name']} ({result['status']})")

graphql_examples()
```

---

أتمنى أن تكون هذه الأمثلة مفيدة! 🚀
