شرح واستخدام Docker في مشروع Agentic-IAM

الملفـات الموجودة:
- Dockerfile: ملف البناء الرئيسي متعدد المراحل لاستخدامه في بيئة الإنتاج الخفيفة.
- Dockerfile.prod: نسخة مُحسّنة للبناء للإنتاج (تستخدم wheel build).
- docker-compose.yml: تكوين كامل للخدمات (app، postgres، redis، prometheus، grafana، إلخ).

ما هدف الدوكر هنا؟
- تعبئة التطبيق وجميع تبعياته في صورة حاوية واحدة قابلة للنشر.
- تشغيل بيئة متكاملة محليًا أو في الخادم عبر تكوين الخدمات في `docker-compose`.
- فصل الخدمات (قاعدة بيانات، redis، مراقبة) لتسهيل الاختبار والتشغيل.

متى نستخدم كل ملف؟
- للتطوير المحلي السريع: استخدم `docker-compose.yml` لتشغيل التطبيق مع postgres وredis وgrafana وprometheus.
- للإنتاج أو بناء صورة نهائية صغيرة: استخدم `Dockerfile` أو `Dockerfile.prod` لبناء صورة مُحسّنة.

أوامر شائعة

1) تشغيل كل الخدمات (تطوير/اختبار):

```bash
# يبني الصورة ثم يشغّل كل الخدمات في الخلفية
docker-compose up --build -d

# متابعة اللوغ
docker-compose logs -f

# إيقاف وإزالة الحاويات والشبكات (لكن تبقى البيانات محفوظة في volumes)
docker-compose down
```

2) تشغيل صورة الإنتاج محليًا (بدون compose):

```bash
# بناء الصورة الإنتاجية
docker build -f Dockerfile.prod -t agentic-iam:prod .

# تشغيل الحاوية مع ضبط متغيرات البيئة (ضع بيانات الحاوية لقاعدة البيانات الحقيقية)
docker run -d --name agentic-iam-prod -p 8000:8000 \
  -e AGENTIC_IAM_DATABASE_URL="postgresql://user:pass@host:5432/agentic_iam" \
  -e AGENTIC_IAM_SECRET_KEY="change-me" \
  agentic-iam:prod
```

3) إعادة تشغيل خدمة واحدة (مثال: فقط التطبيق):

```bash
docker-compose up -d --no-deps --build agentic-iam
```

إدارة الإعدادات الحساسة
- لا تحفظ الأسرار في `docker-compose.yml`. أنشئ ملف `.env` في جذر المشروع أو استخدم نظام إدارة أسرار (Vault, Key Vault).
- لتمرير `.env`:

```bash
docker-compose --env-file .env up -d
```

ملاحظات عن التخزين والمنافذ
- البيانات الدائمة من Postgres وRedis محفوظة في volumes المسماة (`postgres_data`, `redis_data`).
- الاستماع الافتراضي للتطبيق على المنفذ `8000` ولوحة التحكم على `8501`.

صحّة الحاوية
- يوجد `HEALTHCHECK` في `Dockerfile` يتحقق من `http://localhost:8000/health`.

خطوات شائعة بعد التشغيل
- تشغيل الترحيلات (إذا تستخدم Alembic):

```bash
# داخل الحاوية (بعد تشغيل compose):
docker-compose exec agentic-iam bash
# ثم داخل الحاوية
alembic upgrade head
```

أمان ونصائح تشغيلية
- غيّر المفاتيح الافتراضية قبل النشر.
- ضع قواعد لنسخ احتياطي لـ Postgres (لا يعتمد فقط على volumes المحلية).
- استخدم شبكة خاصة عند النشر في سيرفرات الإنتاج.

ملفات ذات صلة في المشروع:
- [Dockerfile](Dockerfile)
- [Dockerfile.prod](Dockerfile.prod)
- [docker-compose.yml](docker-compose.yml)

هل تريد أن أضيف ملف `docker-compose.override.yml` للتطوير (مونت للمجلدات، تفعيل hot-reload)، أم أُنشئ مثال `.env.example` مع المتغيرات الأساسية؟