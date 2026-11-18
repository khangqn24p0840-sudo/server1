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

    def test_normalizes_and_bounds_conversation_memory(self):
        result = server.normalize_conversation_analysis(json.dumps({
            "risk_score": 44,
            "conversation_memory": {
                "summary": "x" * 1600,
                "key_facts": [f"fact {index}" for index in range(12)],
                "behavior_patterns": ["pattern"],
                "open_questions": ["question"],
            },
        }))
        self.assertEqual(len(result["conversation_memory"]["summary"]), 1200)
        self.assertEqual(len(result["conversation_memory"]["key_facts"]), 8)
        self.assertEqual(result["conversation_memory"]["behavior_patterns"], ["pattern"])

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

    def test_endpoint_receives_previous_memory_and_returns_updated_memory(self):
        headers = self.register()
        raw = json.dumps({
            "risk_score": 75,
            "summary": "Cuộc trò chuyện có chuyển biến đáng ngờ.",
            "evidence": ["Sau khi tạo lòng tin, đối phương yêu cầu phí trước."],
            "recommended_action": "Không chuyển tiền; xác minh qua kênh chính thức.",
            "confidence": "HIGH",
            "conversation_memory": {
                "summary": "Ban đầu tạo lòng tin, sau đó yêu cầu khoản phí.",
                "key_facts": ["Đối phương tự nhận hỗ trợ hồ sơ."],
                "behavior_patterns": ["Chuyển từ thân thiện sang thúc ép."],
                "open_questions": ["Chưa xác minh được danh tính."],
            },
        }, ensure_ascii=False)
        previous = {
            "summary": "Đối phương ban đầu trò chuyện thân thiện.",
            "key_facts": ["Chưa yêu cầu tiền ở giai đoạn đầu."],
            "behavior_patterns": ["Tạo lòng tin."],
            "open_questions": [],
        }
        with patch.object(server, "GEMINI_API_KEY", "test-gemini-key"), \
             patch.object(server, "gemini", return_value=raw) as gemini_call:
            response = self.client.post(
                "/api/monitor/conversation",
                json={
                    "memory": previous,
                    "messages": [
                        {"sender": "Người lạ", "text": "Mình sẽ hỗ trợ bạn.", "timestamp": 1000},
                        {"sender": "Người lạ", "text": "Bạn cần đóng phí xác minh.", "timestamp": 2000},
                    ],
                },
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        prompt = gemini_call.call_args.args[1]
        self.assertIn("Đối phương ban đầu trò chuyện thân thiện", prompt)
        self.assertEqual(
            response.get_json()["conversation_memory"]["behavior_patterns"],
            ["Chuyển từ thân thiện sang thúc ép."],
        )

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

    def test_android_chatbot_text_analysis_updates_admin_chat_metrics(self):
        headers = self.register()
        raw = json.dumps({
            "risk": 72,
            "reasons": ["Yêu cầu chuyển khoản"],
            "advice": "Không chuyển tiền; hãy xác minh qua kênh chính thức.",
        }, ensure_ascii=False)
        with patch.object(server, "text_ai", return_value=raw), \
             patch.object(server, "record_ai_status") as record:
            response = self.client.post(
                "/api/analyze/text",
                json={"text": "Tin nhắn yêu cầu chuyển khoản để xác minh tài khoản."},
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        record.assert_called_once()
        self.assertEqual(record.call_args.args[0], "chat")
        self.assertEqual(record.call_args.args[1], "success")

    def test_android_chatbot_gemini_503_fallback_updates_failure_metric(self):
        headers = self.register()
        with patch.object(server, "text_ai", return_value=None), \
             patch.object(server, "record_ai_status") as record:
            response = self.client.post(
                "/api/analyze/text",
                json={"text": "Tin nhắn yêu cầu chuyển khoản để xác minh tài khoản."},
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        record.assert_called_once()
        self.assertEqual(record.call_args.args[0], "chat")
        self.assertEqual(record.call_args.args[1], "failure")

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


class AiActivityHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.app.config.update(TESTING=True)
        cls.client = server.app.test_client()

    def setUp(self):
        with server.sqlite3.connect(server.DB_PATH) as conn:
            conn.execute("DELETE FROM ai_activity")

    def test_preview_redacts_credentials_phone_email_and_url_parameters(self):
        preview = server.sanitize_ai_preview(
            "OTP: 123456, mật khẩu: MySecret, gọi 0912345678, mail a@b.com "
            "và https://example.vn/check?token=private"
        )
        for secret in ("123456", "MySecret", "0912345678", "a@b.com", "token=private"):
            self.assertNotIn(secret, preview)
        self.assertIn("[đã ẩn]", preview)
        self.assertIn("https://example.vn/check", preview)

    def test_activity_endpoint_shows_sanitized_request_and_failure_reason(self):
        server.record_ai_status(
            "chat", "failure", server.time.perf_counter() - 0.02,
            "Kiểm tra tin nhắn OTP: 123456 từ 0912345678",
            "Gemini tạm thời quá tải (HTTP 503 / UNAVAILABLE). Thử lại sau.", 503,
        )
        with patch.object(server, "ADMIN_KEY", "test-admin-key"):
            response = self.client.get(
                "/admin/ai-activity?feature=chat",
                headers={"X-Admin-Key": "test-admin-key"},
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        item = payload["items"][0]
        self.assertEqual(item["feature_label"], "Chatbot thông thường")
        self.assertEqual(item["status_label"], "Thất bại")
        self.assertEqual(item["provider_code"], 503)
        self.assertIn("503", item["failure_reason"])
        self.assertNotIn("123456", item["request_preview"])
        self.assertNotIn("0912345678", item["request_preview"])

    def test_monitor_without_gemini_key_is_recorded_with_reason(self):
        email = f"activity-{uuid.uuid4().hex[:8]}@example.test"
        registered = self.client.post(
            "/api/register",
            json={"email": email, "password": "test-password-123", "username": "Activity"},
        )
        self.assertEqual(registered.status_code, 200, registered.get_json())
        headers = {"Authorization": "Bearer " + registered.get_json()["token"]}
        with patch.object(server, "GEMINI_API_KEY", ""):
            response = self.client.post(
                "/api/monitor/conversation",
                json={"messages": [{"sender": "Người gửi", "text": "Nội dung thử", "timestamp": 1000}]},
                headers=headers,
            )
        self.assertEqual(response.status_code, 503)
        with server.sqlite3.connect(server.DB_PATH) as conn:
            row = conn.execute(
                "SELECT status, request_preview, failure_reason FROM ai_activity "
                "WHERE feature='monitor' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(row[0], "failure")
        self.assertIn("Gemini chưa được cấu hình", row[1])
        self.assertIn("API Key", row[2])


    def test_activity_endpoint_requires_admin_key(self):
        response = self.client.get("/admin/ai-activity")
        self.assertIn(response.status_code, (403, 404))

    def test_clear_activity_endpoint_deletes_rows(self):
        server.record_ai_status("monitor", "failure", request_preview="Phân tích hội thoại (2 tin nhắn).",
                                failure_reason="Gemini HTTP 503", provider_code=503)
        with patch.object(server, "ADMIN_KEY", "test-admin-key"):
            response = self.client.delete(
                "/admin/ai-activity",
                headers={"X-Admin-Key": "test-admin-key"},
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["deleted"], 1)


class AdminAiStatusTests(unittest.TestCase):
    def test_ai_status_includes_server_clock_and_monitor_usage(self):
        server.app.config.update(TESTING=True)
        client = server.app.test_client()
        server.record_ai_status("monitor", "success", server.time.perf_counter() - 0.01)
        with patch.multiple(server, ADMIN_KEY="test-admin-key",
                            GEMINI_API_KEY="not-a-real-key", GEMINI_MODEL="gemini-test"):
            response = client.get("/admin/ai-status", headers={"X-Admin-Key": "test-admin-key"})
        self.assertEqual(response.status_code, 200, response.get_json())
        data = response.get_json()
        self.assertTrue(data["server"]["ok"])
        self.assertGreater(data["server"]["started_at"], 0)
        self.assertTrue(data["gemini"]["configured"])
        self.assertEqual(data["gemini"]["provider"], "gemini")
        self.assertGreaterEqual(data["monitor_chat"]["success"], 1)
        self.assertIsNotNone(data["monitor_chat"]["last_at"])
        self.assertEqual(data["gemini"]["last_call_from"], "Theo dõi chat")
        self.assertNotIn("api_key", data["gemini"])


if __name__ == "__main__":
    unittest.main()