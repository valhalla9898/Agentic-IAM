"""
FAQ Engine - Smart Question Answering with Multiple Response Options
Supports Arabic & English with spelling correction and fuzzy matching
"""

import json
import os
import re
from difflib import SequenceMatcher
from typing import Dict, List


class FAQEngine:
    def __init__(self, faq_file: str = "data/faq_questions.json"):
        self.faq_file = faq_file
        self.faq_data = self._load_faq()
        self.question_cache = {}
        self.categories_list = []
        self._build_cache()

    def _load_faq(self) -> Dict:
        """Load FAQ data from JSON file"""
        if os.path.exists(self.faq_file):
            try:
                with open(self.faq_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading FAQ file: {e}")
                return {}
        return {}

    def _build_cache(self):
        """Build searchable cache of all questions"""
        self.question_cache = {}
        self.categories_list = []
        for category_obj in self.faq_data.get("categories", []):
            cat_name = category_obj.get("category", "")
            if cat_name:
                self.categories_list.append(cat_name)
            for item in category_obj.get("items", []):
                # Add category info to item for metadata retrieval
                item["category"] = cat_name
                q_en = item.get("question_en", "").lower()
                q_ar = item.get("question_ar", "").lower()
                if q_en:
                    self.question_cache[q_en] = item
                if q_ar:
                    self.question_cache[q_ar] = item

    def correct_spelling(self, text: str) -> str:
        """Correct common spelling mistakes"""
        corrections = [
            # Arabic corrections (placeholders - review needed)
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", " "),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            # English corrections
            ("paswword", "password"),
            ("pasword", "password"),
            ("authentification", "authentication"),
            ("authnetication", "authentication"),
            ("usere", "user"),
            ("usres", "users"),
            ("agentt", "agent"),
            ("agnet", "agent"),
            ("permissi", "permission"),
            ("permissio", "permission"),
        ]

        result = text.lower()
        for typo, correct in corrections:
            if not typo:
                continue
            result = re.sub(r"\b" + re.escape(typo) + r"\b", correct, result)
        return result

    def translate_to_english(self, text: str) -> str:
        """Translate Arabic to English (simple keyword mapping)"""
        translation_map = [
            ("", "login"),
            ("", "register"),
            ("", "user"),
            ("", "agent"),
            ("", "permission"),
            ("", "role"),
            ("", "security"),
            ("", "encryption"),
            (" ", "password"),
            ("", "authentication"),
            ("", "report"),
            ("", "analytics"),
            ("", "risk"),
            ("", "assessment"),
            ("", "monitoring"),
            ("", "system"),
            ("", "account"),
            ("", "management"),
            ("", "create"),
            ("", "delete"),
            ("", "edit"),
            ("", "view"),
            ("", "search"),
            ("", "filter"),
            ("", "export"),
            ("", "import"),
            ("", "save"),
            ("", "cancel"),
            ("", "confirm"),
            ("", "error"),
            ("", "success"),
            ("", "failed"),
        ]

        result = text
        for ar, en in translation_map:
            if not ar.strip():
                continue
            result = re.sub(r"\b" + re.escape(ar) + r"\b", en, result, flags=re.UNICODE)
        return result

    def normalize_question(self, question: str) -> str:
        """Normalize question for better matching"""
        # Correct spelling
        corrected = self.correct_spelling(question)
        # Remove extra spaces
        normalized = " ".join(corrected.split())
        return normalized

    def find_similar_questions(self, user_question: str, top_k: int = 5) -> List[Dict]:
        """Find similar questions using fuzzy matching"""
        normalized = self.normalize_question(user_question)

        # Try direct match first
        if normalized in self.question_cache:
            return [self.question_cache[normalized]]

        # Fuzzy match
        similarities = []
        for cached_q, item in self.question_cache.items():
            ratio = SequenceMatcher(None, normalized, cached_q).ratio()
            if ratio > 0.5:  # At least 50% similar
                similarities.append((ratio, item))

        # Sort by similarity and return top k
        similarities.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in similarities[:top_k]]

    def get_answers(self, user_question: str, top_k: int = 5) -> List[Dict]:
        """Get multiple answer options for a question"""
        # Find similar questions
        similar_questions = self.find_similar_questions(user_question, top_k=3)

        answers = []
        for item in similar_questions:
            answer_options = item.get("answers", [])
            for i, answer in enumerate(answer_options[:top_k]):
                answers.append(
                    {
                        "question": item.get("question_en", ""),
                        "answer": answer.get("text", ""),
                        "category": item.get("category", "General"),
                        "option_num": i + 1,
                        "related_topics": answer.get("related_topics", []),
                        "difficulty": answer.get("difficulty", "beginner"),
                    }
                )

        return answers[:top_k]

    def format_answers_for_display(self, answers: List[Dict]) -> str:
        """Format multiple answers for display"""
        if not answers:
            return "❌ No answers found. Try asking with different keywords."

        output = []
        output.append(f"Found {len(answers)} answer options:\n")
        output.append("=" * 60)

        for i, answer in enumerate(answers, 1):
            output.append(f"\n**Option {i}** 📌")
            output.append(f"Category: {answer['category']}")
            output.append(f"Level: {answer['difficulty']}")
            output.append(f"\n{answer['answer']}")

            if answer.get("related_topics"):
                output.append(f"\nRelated Topics: {', '.join(answer['related_topics'])}")

            output.append("\n" + "-" * 60)

        output.append("\n✨ Click on an option number above to get more details!")
        return "\n".join(output)

    def get_faq_categories(self) -> List[str]:
        """Get list of all FAQ categories"""
        return self.categories_list

    def get_questions_by_category(self, category: str) -> List[Dict]:
        """Get all questions in a specific category"""
        results = []
        for item in self.question_cache.values():
            if item.get("category") == category:
                results.append(item)
        return results

    def save_faq(self, data: Dict):
        """Save FAQ data to file"""
        os.makedirs(os.path.dirname(self.faq_file), exist_ok=True)
        with open(self.faq_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# Initialize global FAQ engine
_faq_engine = None


def get_faq_engine() -> FAQEngine:
    """Get or initialize the FAQ engine"""
    global _faq_engine
    if _faq_engine is None:
        _faq_engine = FAQEngine()
    return _faq_engine
