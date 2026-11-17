import os
import tempfile
import unittest
import uuid
from pathlib import Path

_TMP = tempfile.TemporaryDirectory(prefix="scamshield-family-test-")
os.environ["DATA_DIR"] = _TMP.name
os.environ["DB_PATH"] = str(Path(_TMP.name) / "test.db")
os.environ["SECRET_KEY"] = "family-chat-test-secret-not-for-production"
os.environ["ADMIN_KEY"] = ""
os.environ["NEWS_ENABLED"] = "false"
os.environ["ALLOW_REGISTRATION"] = "true"

import server


class FamilyChatApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.app.config.update(TESTING=True)
        cls.client = server.app.test_client()

    def setUp(self):
        server._hits.clear()

    def register(self, label):
        email = f"{label}-{uuid.uuid4().hex[:8]}@example.test"
        response = self.client.post(
            "/api/register",
            json={"email": email, "password": "test-password-123", "username": label.title()},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        return {"Authorization": "Bearer " + response.get_json()["token"]}

    def create_room(self, headers, name="Gia đình nhỏ"):
        response = self.client.post("/api/family/chats", json={"name": name}, headers=headers)
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["id"]

    def create_invite(self, headers, room_id):
        response = self.client.post(f"/api/family/chats/{room_id}/invite", headers=headers)
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()["invite_code"]

    def test_create_invite_join_send_and_read(self):
        mother = self.register("Mother")
        child = self.register("Child")
        outsider = self.register("Outsider")
        room_id = self.create_room(mother)

        denied = self.client.get(f"/api/family/chats/{room_id}/messages", headers=outsider)
        self.assertEqual(denied.status_code, 404)

        code = self.create_invite(mother, room_id)
        joined = self.client.post(
            "/api/family/chats/join", json={"invite_code": code.lower()}, headers=child
        )
        self.assertEqual(joined.status_code, 200, joined.get_json())
        self.assertEqual(joined.get_json()["chat_id"], room_id)

        sent = self.client.post(
            f"/api/family/chats/{room_id}/messages",
            json={"body": "Mọi người về nhà nhé"}, headers=mother,
        )
        self.assertEqual(sent.status_code, 201, sent.get_json())

        rooms = self.client.get("/api/family/chats", headers=child).get_json()["chats"]
        self.assertEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["unread_count"], 1)
        self.assertEqual(rooms[0]["last_message"], "Mọi người về nhà nhé")

        messages = self.client.get(
            f"/api/family/chats/{room_id}/messages?limit=50", headers=child
        ).get_json()["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["body"], "Mọi người về nhà nhé")
        self.assertFalse(messages[0]["mine"])
        self.assertTrue(messages[0]["sender_name"])

        after_read = self.client.get("/api/family/chats", headers=child).get_json()["chats"]
        self.assertEqual(after_read[0]["unread_count"], 0)

        reply = self.client.post(
            f"/api/family/chats/{room_id}/messages",
            json={"body": "Con đã về ạ"}, headers=child,
        )
        self.assertEqual(reply.status_code, 201)
        mother_messages = self.client.get(
            f"/api/family/chats/{room_id}/messages", headers=mother
        ).get_json()["messages"]
        self.assertEqual([m["body"] for m in mother_messages], ["Mọi người về nhà nhé", "Con đã về ạ"])
        self.assertFalse(mother_messages[-1]["mine"])

        denied_send = self.client.post(
            f"/api/family/chats/{room_id}/messages",
            json={"body": "Tin nhắn không được phép"}, headers=outsider,
        )
        self.assertEqual(denied_send.status_code, 404)

    def test_message_and_room_name_validation(self):
        member = self.register("Parent")
        bad_room = self.client.post("/api/family/chats", json={"name": " "}, headers=member)
        self.assertEqual(bad_room.status_code, 400)

        room_id = self.create_room(member)
        empty = self.client.post(
            f"/api/family/chats/{room_id}/messages", json={"body": " "}, headers=member
        )
        self.assertEqual(empty.status_code, 400)
        too_long = self.client.post(
            f"/api/family/chats/{room_id}/messages",
            json={"body": "x" * 2001}, headers=member,
        )
        self.assertEqual(too_long.status_code, 400)

    def test_owner_leave_promotes_oldest_remaining_member(self):
        owner = self.register("Owner")
        member = self.register("Member")
        room_id = self.create_room(owner)
        code = self.create_invite(owner, room_id)
        joined = self.client.post(
            "/api/family/chats/join", json={"invite_code": code}, headers=member
        )
        self.assertEqual(joined.status_code, 200)

        leave = self.client.post(f"/api/family/chats/{room_id}/leave", headers=owner)
        self.assertEqual(leave.status_code, 200)
        members = self.client.get(
            f"/api/family/chats/{room_id}/members", headers=member
        ).get_json()["members"]
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]["role"], "owner")
        self.assertTrue(members[0]["mine"])

    def test_only_owner_can_delete_room(self):
        owner = self.register("LeadParent")
        member = self.register("FamilyMember")
        room_id = self.create_room(owner)
        code = self.create_invite(owner, room_id)
        self.client.post("/api/family/chats/join", json={"invite_code": code}, headers=member)
        denied = self.client.delete(f"/api/family/chats/{room_id}", headers=member)
        self.assertEqual(denied.status_code, 403)
        deleted = self.client.delete(f"/api/family/chats/{room_id}", headers=owner)
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(
            self.client.get("/api/family/chats", headers=member).get_json()["chats"], []
        )


if __name__ == "__main__":
    unittest.main()