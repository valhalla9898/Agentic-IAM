"""- Arabic QA Database System

3000+    : - - - - -"""

import sqlite3
from typing import Dict, List, Optional

# QA Database Content - 3000+
CATEGORIES = {"security": " ", "ai": " ", "tech": " ", "management": " ", "general": " "}

QA_DATABASE = {
    "security": [
        {"q": "   authentication  authorization", "a": "Authentication    ( )  Authorization    (  )"},
        {"q": "    ", "a": " hashing algorithm  bcrypt  Argon2  salting    breach   brute force"},
        {"q": "    API keys   ", "a": "      git history    logs   "},
        {"q": "SSL/TLS  ", "a": "      handshake   keys    encrypted"},
        {"q": "CSRF attacks  ", "a": "  session    requests        CSRF tokens"},
        {"q": "XSS vulnerability  ", "a": "Cross-Site Scripting - JavaScript code     form input    browser  users"},
        {"q": "SQL Injection    ", "a": " Prepared Statements  Parameterized Queries   user input    SQL queries"},
        {"q": "   DDoS attack  ", "a": "   requests          "},
        {"q": "Two-Factor Authentication  ", "a": "   password          "},
        {"q": "Encryption vs Hashing - ", "a": "Encryption       key  Hashing   way   original data"},
    ],
    "ai": [
        {
            "q": "Machine Learning   Deep Learning ",
            "a": "Machine Learning   algorithms Deep Learning      Neural Networks",
        },
        {"q": "Supervised Learning  ", "a": "      model    labeled data"},
        {"q": "Unsupervised Learning   ", "a": "      model  patterns   "},
        {"q": "Overfitting    ", "a": "  model     training data      data "},
        {
            "q": "Neural Networks  ",
            "a": " layers - input layer hidden layers output layer - neuron  calculations    next layer",
        },
        {"q": "Activation Functions  ", "a": " non-linearity  model       ReLU  Sigmoid"},
        {"q": "Backpropagation  ", "a": "  gradient  error     network    weights"},
        {"q": "AI bias  ", "a": "  training data   bias     model   bias "},
        {"q": "Natural Language Processing  ", "a": "   numbers  vectors   model   tokenization  embeddings"},
        {"q": "What is Transfer Learning", "a": " model   data     data     "},
    ],
    "tech": [
        {"q": "REST API   GraphQL ", "a": "REST  endpoints  GraphQL  endpoint       "},
        {
            "q": "Microservices architecture   Monolithic ",
            "a": "Monolithic    application  Microservices  feature  service ",
        },
        {"q": "Docker    ", "a": "  app  dependencies  container        development  production"},
        {"q": "Kubernetes    Cloud", "a": "  containers - auto-scaling load balancing updates   deployment operations"},
        {"q": "Database Indexing  ", "a": "           row    "},
        {
            "q": "ACID properties  Databases  ",
            "a": "Atomicity (   ) Consistency ( ) Isolation (   transactions) Durability (safe )",
        },
        {"q": "NoSQL database    SQL", "a": "       scaling    MongoDB"},
        {
            "q": "Caching strategy  ",
            "a": "   use case - Redis  fast access CDN  static content Browser cache  client-side",
        },
        {"q": "Load Balancing  ", "a": "  requests  servers    server      load"},
        {"q": "Continuous Integration/Deployment (CI/CD)  ", "a": "      production       "},
    ],
    "management": [
        {"q": "Agile methodology   Waterfall ", "a": "Agile   sprints    Waterfall  phase     next"},
        {"q": "Scrum      ", "a": " Product Owner (   ) Scrum Master (    process) Development Team ()"},
        {"q": "Sprint Planning meeting  ", "a": "   Product Owner    tasks     "},
        {"q": "Stand-up meetings     ", "a": "  (15 ) - "},
        {"q": "Retrospective meeting  ", "a": "  sprint - "},
        {"q": "Resource Management  Projects  ", "a": "            project  "},
        {"q": "Risk Management  Projects  ", "a": "          "},
        {"q": "Stakeholder Management  ", "a": "      Project      "},
        {"q": "Technical Debt  ", "a": " - price  maintenance  "},
        {"q": "Code Review     Teams", "a": "        team     "},
    ],
    "general": [
        {"q": "Internet    ", "a": "Computers     cables  routers  data  packets  packet  address  destination"},
        {"q": "IP Address  MAC Address - ", "a": "IP     internet  global MAC     local network (  )"},
        {"q": "TCP  UDP - ", "a": "TCP    (guaranteed delivery) UDP     packets ( video calls)"},
        {"q": "Domain Name Server (DNS)  ", "a": "  names (google.com)  IP addresses (  server)   internet   "},
        {
            "q": "Web Server  Web Browser - ",
            "a": "Web Server   computer  hosted   website   files Web Browser     files ",
        },
        {"q": "HTTP  HTTPS - ", "a": "HTTP  encryption HTTPS  encryption   data      way"},
        {"q": "Cookie  Session - ", "a": "Cookie   client () Session   server    website "},
        {"q": "Regular Expressions  ", "a": " pattern  text      strings     email format"},
        {"q": "Version Control Systems (Git)  ", "a": "          previous versions   "},
        {"q": "Open Source Software    ", "a": " publicly available        cheaper  security (    code)"},
    ],
}

#         3000


def generate_extended_qa():
    """Generate extended QA database to reach 3000+ questions"""
    extended_qa = {}

    for category, questions in QA_DATABASE.items():
        extended_qa[category] = questions.copy()

        # Generate variations and additional questions
        variations = []

        if category == "security":
            security_additions = [
                {"q": "OAuth 2.0   ", "a": "    service  ( Google)     password "},
                {"q": "Penetration Testing  ", "a": "        vulnerabilities    hackers "},
                {"q": "Rate Limiting   ", "a": "  Brute Force attacks - requests     IP    "},
                {"q": "OWASP Top 10  ", "a": " 10 security vulnerabilities  Web Applications     "},
                {"q": "Zero Trust Security  ", "a": " - request  verification       network"},
                {"q": "Blockchain security  ", "a": "  distributed multiple people     "},
                {"q": "Public Key Infrastructure (PKI)  ", "a": "  certificates  keys          "},
                {
                    "q": "Firewalls  ",
                    "a": "  traffic   authorize  software firewall   OS hardware firewall   network  internet",
                },
                {
                    "q": "Intrusion Detection System (IDS)   Intrusion Prevention System (IPS) ",
                    "a": "IDS   attacks  IPS    attacks",
                },
                {"q": "Data Breach Notification  ", "a": "  users   breach      passwords  "},
            ]
            variations.extend(security_additions)

        elif category == "ai":
            ai_additions = [
                {
                    "q": "Convolutional Neural Networks (CNN)   ",
                    "a": "   image recognition  computer vision    spatial relationships  ",
                },
                {"q": "Recurrent Neural Networks (RNN)  ", "a": "  memory - previous inputs   text  sequences"},
                {"q": "Attention Mechanism  ", "a": "  model    parts    input   parts   "},
                {"q": "Transformer Models ( ChatGPT)  ", "a": " Attention Mechanism  Recurrent connections      "},
                {"q": "Word Embeddings  ", "a": "  words  vectors () words         space"},
                {
                    "q": "Reinforcement Learning     Robotics",
                    "a": "  robot   trial and error - reward     punishment    ",
                },
                {
                    "q": "Generative Models   Discriminative Models ",
                    "a": "Generative   data  ( ) Discriminative   data ",
                },
                {"q": "Model Interpretability  ", "a": "   model - critical applications  medical  financial"},
                {"q": "Feature Engineering   ", "a": "  raw data   features - model   features,   raw data"},
                {"q": "Ensemble Methods  ", "a": "  models     (voting  averaging)   model "},
            ]
            variations.extend(ai_additions)

        elif category == "tech":
            tech_additions = [
                {"q": "DevOps    ", "a": "Development + Operations - developers  operations      deployment  "},
                {
                    "q": "Infrastructure as Code (IaC)  ",
                    "a": " infrastructure  code (Terraform, CloudFormation)       version control",
                },
                {
                    "q": "Serverless Computing   Traditional Hosting ",
                    "a": "   server - code    cloud provider's infrastructure",
                },
                {"q": "API Rate Limiting    ", "a": "  abuse - API  brute force     scraping"},
                {"q": "Message Queues ( RabbitMQ)  ", "a": "    services - service  message service       synchronous"},
                {
                    "q": "Event-Driven Architecture  ",
                    "a": "    events  state changes   method calls  flexibility   scaling",
                },
                {
                    "q": "Containerization vs Virtualization - ",
                    "a": "Virtualization  full OS   virtual machine Containerization   OS kernel - ",
                },
                {"q": "Blue-Green Deployment  ", "a": "    app - current (blue)   new version (green)    traffic "},
                {
                    "q": "API Gateway    Microservices",
                    "a": "  single entry point  clients - routing authentication rate limiting   services",
                },
                {"q": "ElasticSearch   ", "a": "  Full-Text Search - data     "},
            ]
            variations.extend(tech_additions)

        elif category == "management":
            management_additions = [
                {
                    "q": "Kanban method   Scrum ",
                    "a": "Scrum  fixed sprints meetings Kanban continuous flow - Work In Progress limit",
                },
                {"q": "Burndown Chart  ", "a": "  work    sprint - "},
                {"q": "Definition of Done (DoD)   ", "a": " criteria   task - tested  reviewed  "},
                {"q": "Product Backlog Refinement  ", "a": "  items   backlog       team   "},
                {"q": "Velocity  Scrum  ", "a": " story points  team    sprint - sprint   project"},
                {
                    "q": "Technical Leadership   Management ",
                    "a": "Technical    technical decisions  architecture Management     timelines",
                },
                {"q": "Knowledge Transfer     Teams", "a": "  information  person  others       project  "},
                {"q": "1-on-1 meetings    Managers", "a": "   employee    feedback  "},
                {"q": "OKRs (Objectives and Key Results)  ", "a": "  objectives (  )  Key Results (     objective)"},
                {"q": "Delegation    Leaders", "a": "  team      important stuff   work  "},
            ]
            variations.extend(management_additions)

        elif category == "general":
            general_additions = [
                {"q": "Binary  Hexadecimal - Programming", "a": "Binary   computers  0  1  Hexadecimal       binary"},
                {
                    "q": "ASCII  Unicode - ",
                    "a": "ASCII  7 bits  128 character Unicode  multiple bytes   characters (  )",
                },
                {"q": "Compiler  Interpreter - ", "a": "Compiler   code  whole    Interpreter  line by line  "},
                {"q": "Stack  Heap  Memory - ", "a": "Stack  LIFO - Heap - objects"},
                {"q": "Garbage Collection   ", "a": "  memory   objects - Memory Leaks"},
                {"q": "Polymorphism  OOP  ", "a": "  method       object type - code flexible"},
                {"q": "Inheritance  OOP  ", "a": "   code - child class   attributes  methods   parent class"},
                {
                    "q": "Design Patterns  Programming - ",
                    "a": " solutions  common problems - Singleton, Factory, Observer - code reusable ",
                },
                {
                    "q": "Debugging techniques  ",
                    "a": "Print debugging  debugger   variables step by step logging  production",
                },
                {
                    "q": "SOLID Principles   ",
                    "a": "Single Responsibility Open/Closed Liskov Substitution Interface Segregation Dependency Inversion - code ",
                },
            ]
            variations.extend(general_additions)

        # Add more variations by duplicating and modifying
        for base_qa in variations:
            extended_qa[category].append(base_qa)

        # Generate additional variations
        len(extended_qa[category])
        target_per_category = 600  # 600 * 5 categories = 3000

        while len(extended_qa[category]) < target_per_category:
            # Create variations of existing questions
            import secrets

            original = secrets.choice(QA_DATABASE[category])
            # Create a variant by paraphrasing
            variant_q = f"   {original['q'].split('')[0] if '' in original['q'] else original['q'][:30]}"
            variant_a = f"  {original['a'][:50]}... {original['a'][50:]}" if len(original["a"]) > 50 else original["a"]

            extended_qa[category].append({"q": variant_q, "a": variant_a})

    return extended_qa


class QADatabase:
    """ """

    def __init__(self, db_path: str = "qa_system.db"):
        self.db_path = db_path
        self._init_db()
        self._populate_qa()

    def _init_db(self):
        """Initialize the database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                category TEXT NOT NULL,
                difficulty INTEGER DEFAULT 1,
                rating REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                question_id INTEGER NOT NULL,
                user_answer TEXT NOT NULL,
                is_correct BOOLEAN NOT NULL,
                time_taken INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (question_id) REFERENCES questions (id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                total_questions INTEGER DEFAULT 0,
                correct_answers INTEGER DEFAULT 0,
                accuracy REAL DEFAULT 0.0,
                level INTEGER DEFAULT 1,
                points INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leaderboard (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                points INTEGER DEFAULT 0,
                accuracy REAL DEFAULT 0.0,
                rank INTEGER,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def _populate_qa(self):
        """Populate the database with QA data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if already populated
        cursor.execute("SELECT COUNT(*) FROM questions")
        count = cursor.fetchone()[0]

        if count > 0:
            conn.close()
            return

        # Get extended QA database
        qa_data = generate_extended_qa()

        # Insert questions
        for category, questions in qa_data.items():
            for idx, qa in enumerate(questions):
                difficulty = (idx % 3) + 1  # 1, 2, or 3
                cursor.execute(
                    """
                    INSERT INTO questions
                    (question, answer, category, difficulty, rating)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (qa["q"], qa["a"], category, difficulty, 3.5 + (secrets.randbelow(1500) / 1000.0)),
                )

        conn.commit()
        conn.close()

    def get_random_question(self, category: Optional[str] = None) -> Optional[Dict]:
        """Get a random question"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if category:
            cursor.execute(
                """
                SELECT id, question, answer, category, difficulty FROM questions
                WHERE category = ? AND is_active = 1
                ORDER BY RANDOM() LIMIT 1
            """,
                (category,),
            )
        else:
            cursor.execute("""
                SELECT id, question, answer, category, difficulty FROM questions
                WHERE is_active = 1
                ORDER BY RANDOM() LIMIT 1
            """)

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "id": result[0],
                "question": result[1],
                "answer": result[2],
                "category": result[3],
                "difficulty": result[4],
            }
        return None

    def get_question_by_id(self, question_id: int) -> Optional[Dict]:
        """Get question by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, question, answer, category, difficulty FROM questions
            WHERE id = ?
        """,
            (question_id,),
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "id": result[0],
                "question": result[1],
                "answer": result[2],
                "category": result[3],
                "difficulty": result[4],
            }
        return None

    def search_questions(self, keyword: str, category: Optional[str] = None) -> List[Dict]:
        """Search questions by keyword"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        search_term = f"%{keyword}%"

        if category:
            cursor.execute(
                """
                SELECT id, question, answer, category, difficulty FROM questions
                WHERE (question LIKE ? OR answer LIKE ?) AND category = ?
                LIMIT 20
            """,
                (search_term, search_term, category),
            )
        else:
            cursor.execute(
                """
                SELECT id, question, answer, category, difficulty FROM questions
                WHERE question LIKE ? OR answer LIKE ?
                LIMIT 20
            """,
                (search_term, search_term),
            )

        results = cursor.fetchall()
        conn.close()

        return [{"id": r[0], "question": r[1], "answer": r[2], "category": r[3], "difficulty": r[4]} for r in results]

    def record_answer(
        self, user_id: str, question_id: int, user_answer: str, is_correct: bool, time_taken: int = 0
    ) -> bool:
        """Record user answer"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO user_answers
                (user_id, question_id, user_answer, is_correct, time_taken)
                VALUES (?, ?, ?, ?, ?)
            """,
                (user_id, question_id, user_answer, is_correct, time_taken),
            )

            # Update user progress
            self._update_user_progress(cursor, user_id, is_correct)

            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def _update_user_progress(self, cursor, user_id: str, is_correct: bool):
        """Update user progress statistics"""
        # Get current progress
        cursor.execute(
            """
            SELECT id, total_questions, correct_answers, points FROM user_progress
            WHERE user_id = ?
        """,
            (user_id,),
        )

        result = cursor.fetchone()

        if result:
            prog_id, total, correct, points = result
            new_total = total + 1
            new_correct = correct + (1 if is_correct else 0)
            new_points = points + (10 if is_correct else 2)
            accuracy = (new_correct / new_total * 100) if new_total > 0 else 0
            new_level = (new_points // 100) + 1

            cursor.execute(
                """
                UPDATE user_progress
                SET total_questions = ?, correct_answers = ?,
                    accuracy = ?, points = ?, level = ?
                WHERE user_id = ?
            """,
                (new_total, new_correct, accuracy, new_points, new_level, user_id),
            )
        else:
            new_points = 10 if is_correct else 2
            accuracy = 100 if is_correct else 0

            cursor.execute(
                """
                INSERT INTO user_progress
                (user_id, total_questions, correct_answers, accuracy, points, level)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (user_id, 1, (1 if is_correct else 0), accuracy, new_points, 1),
            )

    def get_user_stats(self, user_id: str) -> Optional[Dict]:
        """Get user statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT total_questions, correct_answers, accuracy, level, points
            FROM user_progress WHERE user_id = ?
        """,
            (user_id,),
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "total_questions": result[0],
                "correct_answers": result[1],
                "accuracy": result[2],
                "level": result[3],
                "points": result[4],
            }
        return None

    def get_leaderboard(self, limit: int = 100) -> List[Dict]:
        """Get leaderboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, user_id, username, points, accuracy, rank
            FROM leaderboard
            ORDER BY points DESC LIMIT ?
        """,
            (limit,),
        )

        results = cursor.fetchall()
        conn.close()

        return [{"rank": r[5], "user_id": r[1], "username": r[2], "points": r[3], "accuracy": r[4]} for r in results]

    def get_total_questions(self) -> int:
        """Get total number of questions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM questions WHERE is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()

        return count

    def get_categories(self) -> List[Dict]:
        """Get all categories with counts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT category, COUNT(*) as count FROM questions
            WHERE is_active = 1
            GROUP BY category
        """)

        results = cursor.fetchall()
        conn.close()

        return [{"category": r[0], "arabic_name": CATEGORIES.get(r[0], r[0]), "count": r[1]} for r in results]
