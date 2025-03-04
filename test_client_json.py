import unittest
import json
import socket
from unittest.mock import MagicMock, patch
from clientjson import (
    hash_password,
    encode_request,
    decode_response,
    send_request_json,
)

class TestClientJSON(unittest.TestCase):
    def test_hash_password(self):
        pwd_hash = hash_password("secret")
        # checking that it is a valid string
        self.assertTrue(len(pwd_hash) == 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in pwd_hash))

    def test_encode_request(self):
        req = {"type": "login", "username": "alice"}
        encoded = encode_request(req)
        # Now, proceed to producing a json string
        self.assertTrue(encoded.endswith("\n"))
        # debugging statement to stripping a new json line
        data = json.loads(encoded.strip())
        self.assertEqual(data["type"], "login")
        self.assertEqual(data["username"], "alice")

    def test_decode_response_valid(self):
        resp_str = '{"status": "ok", "data": ["Test message"]}\n'
        decoded = decode_response(resp_str)
        self.assertEqual(decoded["status"], "ok")
        self.assertEqual(decoded["data"], ["Test message"])

    def test_decode_response_invalid(self):
        resp_str = '{"status": "ok", "data": ["Test message"]'
        decoded = decode_response(resp_str)
        self.assertEqual(decoded["status"], "error")
        self.assertIn("Invalid JSON response", decoded["error"])

    @patch('client.socket.socket')
    def test_send_request_json_success(self, mock_socket_class):
        """
        Test the happy-path scenario of send_request_json with a mocked socket.
        """
        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance

        # Simulate the event in which the jsobn sends a response
        mock_socket_instance.recv.side_effect = [
            b'{"status": "ok", "data": ["All good"]}\n'
        ]

        s = socket.socket()  # Will be the mock
        req = {"type": "login", "username": "alice"}
        response = send_request_json(s, req)
        
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["data"], ["All good"])

        # Making sure the socket is receiving the right thing
        sent_data = mock_socket_instance.sendall.call_args[0][0]
        self.assertIn(b'"type": "login"', sent_data)
        self.assertIn(b'"username": "alice"', sent_data)

    @patch('client.socket.socket')
    def test_send_request_json_server_closes_connection(self, mock_socket_class):
        """
        Sometimes the server might close before it even starts 
        """
        mock_socket_instance = MagicMock()
        mock_socket_class.return_value = mock_socket_instance
        # Server closing the connection 
        mock_socket_instance.recv.side_effect = [b'']

        s = socket.socket()
        req = {"type": "login", "username": "alice"}

        with self.assertRaises(ConnectionError) as context:
            send_request_json(s, req)

        self.assertIn("Server closed connection.", str(context.exception))

if __name__ == "__main__":
    unittest.main()
