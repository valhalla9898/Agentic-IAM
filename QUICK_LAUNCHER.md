# Quick Start - Project Launcher

هذا الدليل يشرح كيفية إنشاء shortcut لتشغيل المشروع بنقرة واحدة.

## على Windows 10/11

### الطريقة السريعة (موصى به):

1. **افتح ملف explorer** واذهب إلى مجلد المشروع
   ```
   C:\Users\Lenovo\Desktop\Agentic-IAM-main
   ```

2. **انقر بزر الفأرة الأيمن على `start_project.bat`**

3. **اختر "Send to" > "Desktop (create shortcut)"**

4. **انقر على الـ shortcut على سطح المكتب لتشغيل المشروع** ✅

### الطريقة اليدوية (إذا لم تنجح الطريقة الأولى):

1. **انقر بزر الفأرة الأيمن على سطح المكتب**
2. **اختر "New" > "Shortcut"**
3. **في خانة الموقع، أدخل:**
   ```
   C:\Users\Lenovo\Desktop\Agentic-IAM-main\start_project.bat
   ```
4. **اضغط "Next"**
5. **أدخل الاسم:** `Agentic-IAM`
6. **اضغط "Finish"**

### اختياري: تغيير الأيقونة

1. **انقر بزر الفأرة الأيمن على الـ shortcut**
2. **اختر "Properties"**
3. **اضغط "Change Icon..."**
4. **ابحث عن أيقونة VS Code:**
   ```
   C:\Users\Lenovo\AppData\Local\Programs\Microsoft VS Code\Code.exe
   ```

---

## على Linux/macOS

### باستخدام Terminal:

```bash
# اجعل الـ script قابل للتنفيذ
chmod +x ~/Desktop/Agentic-IAM-main/start_project.sh

# قم بتشغيله
~/Desktop/Agentic-IAM-main/start_project.sh
```

### إنشاء Desktop Shortcut (Linux GNOME):

1. **انسخ ملف `.desktop`:**
   ```bash
   cp ~/Desktop/Agentic-IAM-main/agentic-iam.desktop ~/Desktop/
   ```

2. **عدّل المسار في الملف:**
   ```bash
   nano ~/Desktop/agentic-iam.desktop
   ```
   
   غيّر هذا السطر:
   ```
   Exec=bash -c "cd /path/to/Agentic-IAM-main && ./start_project.sh"
   ```
   
   إلى:
   ```
   Exec=bash -c "cd ~/Desktop/Agentic-IAM-main && ./start_project.sh"
   ```

3. **اجعله قابل للتنفيذ:**
   ```bash
   chmod +x ~/Desktop/agentic-iam.desktop
   ```

4. **انقر عليه لتشغيل المشروع** ✅

---

## ماذا يفعل الـ Launcher؟

عندما تضغط على الـ shortcut:

✅ **ينشئ بيئة افتراضية** (إذا لم تكن موجودة)  
✅ **يثبت المكتبات المطلوبة**  
✅ **يفتح VS Code** في المجلد  
✅ **يشغّل API Server** على `http://localhost:8000`  
✅ **يشغّل Streamlit Dashboard** على `http://localhost:8501`  

### الخدمات المتاحة بعد التشغيل:

| الخدمة | الرابط |
|--------|--------|
| **API Server** | http://localhost:8000 |
| **API Documentation** | http://localhost:8000/docs |
| **Swagger UI** | http://localhost:8000/redoc |
| **Streamlit Dashboard** | http://localhost:8501 |
| **VS Code Editor** | يفتح تلقائياً |

---

## استكشاف الأخطاء

### إذا لم يفتح المشروع:

1. **تأكد من وجود Python 3.9+:**
   ```bash
   python --version
   ```

2. **تأكد من وجود pip:**
   ```bash
   pip --version
   ```

3. **جرب تشغيل البرنامج النصي يدويًا:**
   
   **Windows:**
   ```cmd
   cd C:\Users\Lenovo\Desktop\Agentic-IAM-main
   start_project.bat
   ```
   
   **Linux/macOS:**
   ```bash
   cd ~/Desktop/Agentic-IAM-main
   ./start_project.sh
   ```

4. **إذا كان هناك خطأ في التثبيت:**
   ```bash
   pip install --upgrade -e .
   ```

---

## الإيقاف

لإيقاف جميع الخدمات:

1. **أغلق نوافذ PowerShell/Command Prompt**
2. **أو اضغط Ctrl+C في كل نافذة**

---

## ملاحظات

- الـ launcher سيفتح **3 نوافذ جديدة** (VS Code + API + Dashboard)
- تأكد من عدم وجود خدمات على المنافذ `8000` و `8501`
- قد تستغرق المرة الأولى وقتاً أطول (لتثبيت المكتبات)
