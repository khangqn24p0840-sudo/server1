import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

_TEST_DATA = tempfile.TemporaryDirectory(prefix="scamshield-monitor-test-")
os.environ.setdefault("DATA_DIR", _TEST_DATA.name)
os.environ.setdefault("DB_PATH", str(Path(_TEST_DATA.name) / "monitor-test.db"))
os.environ.setdefault("SECRET_KEY", "conversation-monitor-test-secret")
os.environ.setdefault("ADMIN_KEY", "")
os.environ.setdefault("NEWS_ENABLED", "false")
os.environ.setdefault("ALLOW_REGISTRATION", "true")

import server


class ConversationMonitorNormalizationTests(unittest.TestCase):
    def test_normalizes_valid_gemini_json(self):
        raw = json.dumps({
            "risk_score": 86.6,
            "summary": "Có dấu hiệu thúc ép chuyển tiền",
            "evidence": ["Yêu cầu nạp tiền", "Hứa hoa hồng cao"],
            "recommended_action": "Dừng giao dịch và xác minh",
            "confidence": "HIGH",
        }, ensure_ascii=False)
        result = server.normalize_conversation_analysis(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["risk_score"], 87)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(len(result["evidence"]), 2)

    def test_clamps_score_and_bounds_evidence(self):
        raw = json.dumps({
            "risk_score": 180,
            "summary": "x" * 900,
            "evidence": ["a", "b", "c", "d", "e", "f"],
            "confidence": "unknown",
        })
        result = server.normalize_conversation_analysis(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(len(result["evidence"]), 5)
        self.assertEqual(result["confidence"], "LOW")
        self.assertLessEqual(len(result["summary"]), 600)

    def test_rejects_invalid_or_missing_risk_score(self):
        self.assertIsNone(server.normalize_conversation_analysis("not json"))
        self.assertIsNone(server.normalize_conversation_analysis('{"risk_score":"high"}'))

    def test_maps_scores_to_risk_levels(self):
        low = server.normalize_conversation_analysis('{"risk_score": 20}')
        medium = server.normalize_conversation_analysis('{"risk_score": 50}')
        high = server.normalize_conversation_analysis('{"risk_score": 90}')
        self.assertEqual(low["risk_level"], "LOW")
        self.assertEqual(medium["risk_level"], "MEDIUM")
        self.assertEqual(high["risk_level"], "HIGH")


class ConversationMonitorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.app.config.update(TESTING=True)
        cls.client = server.app.test_client()

    def setUp(self):
        server._hits.clear()

    def register(self):
        email = f"monitor-{uuid.uuid4().hex[:8]}@example.test"
        response = self.client.post(
            "/api/register",
            json={"email": email, "password": "test-password-123", "username": "Monitor"},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        return {"Authorization": "Bearer " + response.get_json()["token"]}

    def test_requires_authentication(self):
        response = self.client.post(
            "/api/monitor/conversation",
            json={"messages": [{"sender": "A", "text": "Xin chào", "timestamp": 1000}]},
        )
        self.assertIn(response.status_code, (401, 403))

    def test_endpoint_calls_gemini_and_returns_bounded_result(self):
        headers = self.register()
        raw = json.dumps({
            "risk_score": 82,
            "summary": "Cuộc trò chuyện chuyển sang yêu cầu nạp tiền.",
            "evidence": ["Yêu cầu nạp tiền trước", "Hứa hoa hồng cao"],
            "recommended_action": "Dừng giao dịch và xác minh độc lập.",
            "confidence": "HIGH",
        }, ensure_ascii=False)
        with patch.object(server, "GEMINI_API_KEY", "test-gemini-key"), \
             patch.object(server, "gemini", return_value=raw) as gemini_call:
            response = self.client.post(
                "/api/monitor/conversation",
                json={"messages": [
                    {"sender": "Người lạ", "text": "Việc nhẹ lương cao", "timestamp": 1000},
                    {"sender": "Người lạ", "text": "Nạp tiền để kích hoạt", "timestamp": 2000},
                ]},
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["risk_level"], "HIGH")
        self.assertEqual(payload["risk_score"], 82)
        self.assertEqual(payload["message_count"], 2)
        self.assertEqual(payload["last_message_timestamp"], 2000)
        self.assertTrue(payload["ai"])
        gemini_call.assert_called_once()

    def test_endpoint_rejects_more_than_twelve_messages(self):
        headers = self.register()
        with patch.object(server, "GEMINI_API_KEY", "test-gemini-key"):
            response = self.client.post(
                "/api/monitor/conversation",
                json={"messages": [
                    {"sender": "A", "text": "Xin chào", "timestamp": i}
                    for i in range(13)
                ]},
                headers=headers,
            )
        self.assertEqual(response.status_code, 400)

    def test_endpoint_rejects_oversized_transcript(self):
        headers = self.register()
        with patch.object(server, "GEMINI_API_KEY", "test-gemini-key"):
            response = self.client.post(
                "/api/monitor/conversation",
                json={"messages": [
                    {"sender": "A", "text": "x" * 800, "timestamp": i}
                    for i in range(8)
                ]},
                headers=headers,
            )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()