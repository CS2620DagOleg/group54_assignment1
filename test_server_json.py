import unittest
import json
from serverjson import (
    users_db,
    handle_request,
    create_account,
    login,
    list_accounts,
    send_message,
    read_new_messages,
    delete_messages,
    delete_account,
    list_messages,
    decode_request,
    encode_response
)

class TestServerJSON(unittest.TestCase):
    def setUp(self):
        """
        Runs before each test, ensuring we start with a fresh users_db.
        """
        users_db.clear()

    def test_decode_request_valid_json(self):
        line_str = '{"type": "login", "username": "alice"}'
        result = decode_request(line_str)
        self.assertEqual(result["type"], "login")
        self.assertEqual(result["username"], "alice")

    def test_decode_request_invalid_json(self):
        line_str = '{"type": "login" "username": "alice"}'  # Missing comma
        result = decode_request(line_str)
        self.assertEqual(result["type"], "unknown")
        self.assertIn("Invalid JSON", result["error"])

    def test_encode_response(self):
        resp = {"status": "ok", "data": ["Test message"]}
        encoded = encode_response(resp)
        # End of File checkings
        self.assertTrue(encoded.endswith("\n"))
        # Can we decode the thing back? 
        decoded = json.loads(encoded.strip())
        self.assertEqual(decoded["status"], "ok")
        self.assertEqual(decoded["data"], ["Test message"])

    # Some tests for handler files 
    def test_create_account_success(self):
        req = {
            "type": "create_account",
            "username": "alice",
            "password": "secret"
        }
        response = create_account(req)
        self.assertEqual(response["status"], "ok")
        self.assertIn("created successfully", response["data"][0])
        self.assertIn("alice", users_db)
        self.assertEqual(users_db["alice"]["password"], "secret")

    def test_create_account_existing_user(self):
        users_db["bob"] = {"password": "bobpass", "messages": []}
        req = {
            "type": "create_account",
            "username": "bob",
            "password": "anotherpass"
        }
        response = create_account(req)
        self.assertEqual(response["status"], "error")
        self.assertIn("Username already taken", response["error"])

    def test_login_success(self):
        # Defining a user 
        users_db["alice"] = {"password": "secret", "messages": []}
        req = {
            "type": "login",
            "username": "alice",
            "password": "secret"
        }
        response = login(req)
        self.assertEqual(response["status"], "ok")
        self.assertIn("logged in successfully", response["data"][0])
        self.assertEqual(response["data"][1], "0")  

    def test_login_wrong_password(self):
        users_db["alice"] = {"password": "secret", "messages": []}
        req = {
            "type": "login",
            "username": "alice",
            "password": "wrongpass"
        }
        response = login(req)
        self.assertEqual(response["status"], "error")
        self.assertIn("Incorrect password", response["error"])

    def test_list_accounts(self):
        users_db["alice"] = {"password": "secret", "messages": []}
        users_db["bob"] = {"password": "bobpass", "messages": []}
        req = {"type": "list_accounts", "pattern": ""}
        response = list_accounts(req)
        self.assertEqual(response["status"], "ok")
        # What would be the single string in response? 
        accounts = response["data"][0].split(",")
        self.assertEqual(set(accounts), {"alice", "bob"})

    def test_send_message_success(self):
        users_db["alice"] = {"password": "secret", "messages": []}
        users_db["bob"] = {"password": "bobpass", "messages": []}
        req = {
            "type": "send_message",
            "from": "alice",
            "to": "bob",
            "content": "Hello Bob"
        }
        response = send_message(req)
        self.assertEqual(response["status"], "ok")
        # So Bob woudld not not read the message 
        self.assertEqual(len(users_db["bob"]["messages"]), 1)
        self.assertFalse(users_db["bob"]["messages"][0]["read"])
        self.assertEqual(users_db["bob"]["messages"][0]["content"], "Hello Bob")

    def test_read_new_messages_partial(self):
        users_db["bob"] = {
            "password": "bobpass",
            "messages": [
                {"from": "alice", "content": "Hello 1", "read": False, "timestamp": "02/10 14:00"},
                {"from": "alice", "content": "Hello 2", "read": False, "timestamp": "02/10 14:01"},
                {"from": "alice", "content": "Hello 3", "read": False, "timestamp": "02/10 14:02"}
            ]
        }
        req = {
            "type": "read_new_messages",
            "username": "bob",
            "count": 2
        }
        response = read_new_messages(req)
        self.assertEqual(response["status"], "ok")
        
        self.assertEqual(response["data"][0], "2")
        # We know that the first 2 messages are read 
        self.assertTrue(users_db["bob"]["messages"][0]["read"])
        self.assertTrue(users_db["bob"]["messages"][1]["read"])
        self.assertFalse(users_db["bob"]["messages"][2]["read"])

    def test_delete_messages_by_index(self):
        users_db["charlie"] = {
            "password": "charliepass",
            "messages": [
                {"from": "alice", "content": "Hi", "read": True, "timestamp": "02/10 14:00"},
                {"from": "bob", "content": "Yo", "read": True, "timestamp": "02/10 14:05"},
                {"from": "alice", "content": "Again", "read": True, "timestamp": "02/10 14:10"}
            ]
        }
        req = {
            "type": "delete_messages",
            "username": "charlie",
            "message_ids": "1,3"
        }
        response = delete_messages(req)
        self.assertEqual(response["status"], "ok")
        # Making the middle message remain for testing 
        self.assertEqual(len(users_db["charlie"]["messages"]), 1)
        self.assertEqual(users_db["charlie"]["messages"][0]["content"], "Yo")

    def test_delete_account(self):
        users_db["dave"] = {"password": "davepass", "messages": []}
        req = {
            "type": "delete_account",
            "username": "dave"
        }
        response = delete_account(req)
        self.assertEqual(response["status"], "ok")
        self.assertNotIn("dave", users_db)

    def test_handle_request_unknown(self):
        req = {"type": "some_unknown_operation"}
        resp = handle_request(req)
        self.assertEqual(resp["status"], "error")
        self.assertIn("Unknown request type", resp["error"])

    # Integration-ish test for handle_request
    def test_handle_request_create_then_login(self):
        # create_account
        req_create = {
            "type": "create_account",
            "username": "eve",
            "password": "evepass"
        }
        resp_create = handle_request(req_create)
        self.assertEqual(resp_create["status"], "ok")

        # login
        req_login = {
            "type": "login",
            "username": "eve",
            "password": "evepass"
        }
        resp_login = handle_request(req_login)
        self.assertEqual(resp_login["status"], "ok")
        self.assertIn("logged in successfully", resp_login["data"][0])

if __name__ == "__main__":
    unittest.main()
