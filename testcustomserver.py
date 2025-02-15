import unittest
from server2 import (
    users_db,
    decode_request,
    handle_request,
    encode_response,
    create_account,
    login,
    list_accounts,
    send_message,
    read_new_messages,
    delete_messages,
    delete_account,
    list_messages,
)

class TestCustomServer(unittest.TestCase):
    def setUp(self):
        # Clearing database before testing, cleaning what is in the memory
        users_db.clear()

    def test_decode_request_version_code(self):
        # Valid request: "1|2|alice|password"
        line = "1|2|alice|hashedpass"
        req = decode_request(line)
        self.assertEqual(req["type"], "login")
        self.assertEqual(req["username"], "alice")
        self.assertEqual(req["password"], "hashedpass")

    def test_decode_request_invalid_version(self):
        line = "999|2|alice|password"
        req = decode_request(line)
        self.assertEqual(req["type"], "unknown")
        self.assertIn("Unsupported version", req["error"])

    def test_decode_request_not_enough_fields(self):
        
        line = "1|4|alice"
        req = decode_request(line)
        self.assertEqual(req["type"], "unknown")
        self.assertIn("Not enough fields for send_message", req["error"])

    def test_encode_response_ok(self):
        resp = {"status": "ok", "data": ["Account created", "ExtraField"]}
        encoded = encode_response(resp)
        self.assertTrue(encoded.startswith("OK|"))
        
        self.assertTrue(encoded.endswith("\n"))
        self.assertIn("Account created", encoded)

    def test_encode_response_error(self):
        resp = {"status": "error", "error": "Something went wrong"}
        encoded = encode_response(resp)
        self.assertTrue(encoded.startswith("ERROR|"))
        self.assertIn("Something went wrong", encoded)

    
    # Test the handler functions individually
    
    def test_create_account_success(self):
        req = {"username": "alice", "password": "secret"}
        resp = create_account(req)
        self.assertEqual(resp["status"], "ok")
        self.assertIn("created successfully", resp["data"][0])
        self.assertIn("alice", users_db)

    def test_create_account_existing_user(self):
        users_db["bob"] = {"password": "bobpass", "messages": []}
        req = {"username": "bob", "password": "newpass"}
        resp = create_account(req)
        self.assertEqual(resp["status"], "error")
        self.assertIn("already taken", resp["error"])

    def test_login_wrong_password(self):
        users_db["alice"] = {"password": "secret", "messages": []}
        req = {"username": "alice", "password": "wrongpass"}
        resp = login(req)
        self.assertEqual(resp["status"], "error")
        self.assertIn("Incorrect password", resp["error"])

    def test_list_accounts_pattern(self):
        users_db["alice"] = {"password": "pass", "messages": []}
        users_db["bob"]   = {"password": "pass", "messages": []}
        users_db["carol"] = {"password": "pass", "messages": []}
        req = {"username": "bob", "pattern": "a"}
        resp = list_accounts(req)
        self.assertEqual(resp["status"], "ok")
        # splitting on comma 
        matches = resp["data"][0].split(",")
        self.assertEqual(set(matches), {"alice", "carol"})

    def test_send_message_success(self):
        users_db["alice"] = {"password": "alicepass", "messages": []}
        users_db["bob"]   = {"password": "bobpass", "messages": []}
        req = {"from": "alice", "to": "bob", "content": "Hello Bob"}
        resp = send_message(req)
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(len(users_db["bob"]["messages"]), 1)
        self.assertFalse(users_db["bob"]["messages"][0]["read"])

    def test_read_new_messages(self):
        users_db["bob"] = {
            "password": "bobpass",
            "messages": [
                {"from": "alice", "content": "Hi1", "read": False, "timestamp": "12/01 10:00"},
                {"from": "alice", "content": "Hi2", "read": False, "timestamp": "12/01 10:01"},
            ]
        }
        req = {"username": "bob", "count": 1}
        resp = read_new_messages(req)
        self.assertEqual(resp["status"], "ok")
        # checking on number of messages 
        self.assertEqual(resp["data"][0], "1")
        # what message is not read 
        self.assertFalse(users_db["bob"]["messages"][1]["read"])

    def test_delete_messages_some(self):
        users_db["charlie"] = {
            "password": "charliepass",
            "messages": [
                {"from": "alice", "content": "One",   "read": True, "timestamp": "X"},
                {"from": "bob",   "content": "Two",   "read": True, "timestamp": "X"},
                {"from": "alice", "content": "Three", "read": True, "timestamp": "X"},
            ]
        }
        req = {"username": "charlie", "message_ids": "1,3"}
        resp = delete_messages(req)
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(len(users_db["charlie"]["messages"]), 1)
        self.assertEqual(users_db["charlie"]["messages"][0]["content"], "Two")

    def test_delete_account(self):
        users_db["dave"] = {"password": "davepass", "messages": []}
        req = {"username": "dave"}
        resp = delete_account(req)
        self.assertEqual(resp["status"], "ok")
        self.assertNotIn("dave", users_db)

    def test_list_messages(self):
        users_db["eve"] = {
            "password": "evepass",
            "messages": [
                {"from": "alice", "content": "ReadOne", "read": True, "timestamp": "X"},
                {"from": "alice", "content": "UnreadOne", "read": False, "timestamp": "X"}
            ]
        }
        req = {"username": "eve"}
        resp = list_messages(req)
        self.assertEqual(resp["status"], "ok")
        # What messages are returned? only the read messages should be the ones returned 
        self.assertEqual(resp["data"][0], "1")  # number of messages returned
        self.assertIn("ReadOne", resp["data"][1])

    
    # Test the top-level handle_request, make sure to test 
    
    def test_handle_request_unknown(self):
        req = {"type": "unknown"}
        resp = handle_request(req)
        self.assertEqual(resp["status"], "error")

if __name__ == "__main__":
    unittest.main()









