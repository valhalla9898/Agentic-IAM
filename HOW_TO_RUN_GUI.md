# تشغيل Dashboard Agentic-IAM

## الطرق المتاحة:

### 1️⃣ **على Windows (الطريقة السهلة):**
```bash
# انقر مرتين على الملف:
run_dashboard.bat
```

### 2️⃣ **من PowerShell/CMD:**
```bash
cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
streamlit run app.py
```

### 3️⃣ **من Terminal (أي نظام):**
```bash
streamlit run app.py
```

### 4️⃣ **مع خيارات إضافية:**
```bash
# تشغيل على منفذ معين
streamlit run app.py --server.port 8501

# تشغيل في وضع التطوير
streamlit run app.py --logger.level=debug

# تشغيل بدون فتح المتصفح تلقائياً
streamlit run app.py --client.showErrorDetails=true
```

## ✅ المتطلبات:

تأكد من تثبيت Streamlit:
```bash
pip install streamlit
```

## 📱 الوصول إلى Dashboard:

بعد التشغيل، سيفتح تلقائياً في المتصفح:
- **العنوان المحلي:** `http://localhost:8501`

## 🛑 إيقاف التطبيق:

- اضغط `Ctrl + C` في Terminal
- أو أغلق نافذة المتصفح

---

## 🎯 الميزات المتاحة:

- 👥 **Agent Management** - إدارة الوكلاء والأجنحة
- 🔐 **Session Management** - إدارة الجلسات
- 📋 **Audit Log** - سجل التدقيق
- ⚙️ **Settings** - الإعدادات
- 📊 **Home Dashboard** - لوحة التحكم الرئيسية
