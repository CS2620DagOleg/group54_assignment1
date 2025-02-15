import unittest
from unittest.mock import patch, MagicMock
import socket


from client2 import (
    hash_password,
    encode_request,
    decode_response,
    send_request_custom
)

class TestCustomClient(unittest.TestCase):
    def test_hash_password(self):
        result = hash_password("secret")
        self.assertEqual(len(result), 64)  
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_encode_request_create_account(self):
        req = {
            "type": "create_account",
            "username": "alice",
            "password": "hashpass"
        }
        out = encode_request(req)
        # Testing what it produces, it should be the same 
        self.assertTrue(out.startswith("1|1|alice|hashpass"))
        self.assertTrue(out.endswith("\n"))

    def test_encode_request_send_message(self):
        req = {
            "type": "send_message",
            "from": "alice",
            "to": "bob",
            "content": "Hello Bob"
        }
        out = encode_request(req)
        
        parts = out.strip().split("|")
        self.assertEqual(parts[0], "1")  
        self.assertEqual(parts[1], "4")  # code for send_message
        self.assertEqual(parts[2], "alice")
        self.assertEqual(parts[3], "bob")
        self.assertEqual(parts[4], "Hello Bob")

    def test_encode_request_unknown_type(self):
        # ment to raise an error 
        req = {"type": "some_unknown_type"}
        with self.assertRaises(ValueError):
            encode_request(req)

    def test_decode_response_ok(self):
        resp_str = "OK|Account 'alice' created successfully\n"
        decoded = decode_response(resp_str)
        self.assertEqual(decoded["status"], "ok")
        self.assertEqual(decoded["data"], ["Account 'alice' created successfully\n"])

    def test_decode_response_error(self):
        resp_str = "ERROR|No such user\n"
        decoded = decode_response(resp_str)
        self.assertEqual(decoded["status"], "error")
        self.assertEqual(decoded["error"], "No such user\n")

    @patch('client2.socket.socket')
    def test_send_request_custom_success(self, mock_socket_class):
        """
        Simulation of a successful test
        """
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance

        # The server response we'll simulate
        mock_sock_instance.recv.side_effect = [
            b'OK|Message sent successfully\n'
        ]

        s = socket.socket()  # Actually returns the mock
        req = {
            "type": "send_message",
            "from": "alice",
            "to": "bob",
            "content": "Hello Bob"
        }
        response = send_request_custom(s, req)

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["data"], ["Message sent successfully"])

        # Check what was sent by the client
        sent_data = mock_sock_instance.sendall.call_args[0][0]
        sent_str  = sent_data.decode("utf-8")
        # e.g. "1|4|alice|bob|Hello Bob\n"
        self.assertIn("|4|alice|bob|Hello Bob\n", sent_str)

    @patch('client2.socket.socket')
    def test_send_request_custom_server_closes_connection(self, mock_socket_class):
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance

        # If recv returns b"", that indicates the server closed the connection
        mock_sock_instance.recv.side_effect = [b'']

        s = socket.socket()
        req = {"type": "login", "username": "u", "password": "p"}
        with self.assertRaises(ConnectionError) as ctx:
            send_request_custom(s, req)
        self.assertIn("Server closed connection", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()
