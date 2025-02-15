import socket
import threading
import re
import logging
import os
import datetime
import json
from datetime import datetime as dt  # for timestamps


# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

HOST = config["server_host"]
PORT = config["server_port"]


# Ensure logs folder
os.makedirs("logs", exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = os.path.join("logs", f"chat_server_{timestamp}.log")

logging.basicConfig(
    filename=log_filename,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logging.info("-------------------------------------------------")
logging.info("Chat Server started.")
logging.info(f"Logging to file: {log_filename}")

# In-memory storage for user data.
# { "alice": { "password": "...", "messages": [ { "from": "bob", "content": "...", "read": False, "timestamp": "02/10 14:37" }, ... ] } }
users_db = {}

# Numeric -> Action mapping
CODE_TO_ACTION = {
    1: "create_account",
    2: "login",
    3: "list_accounts",
    4: "send_message",
    5: "read_new_messages",
    6: "delete_messages",
    7: "delete_account",
    8: "list_messages"
}

def encode_response(resp: dict) -> str:
    """
    Encode a response dictionary into our custom protocol string.

    Success response: "OK|field1|field2|...|fieldN\n"
    Error response:   "ERROR|error message\n"
    """
    if resp["status"] == "ok":
        data_fields = resp.get("data", [])
        return "OK|" + "|".join(str(x) for x in data_fields) + "\n"
    else:
        return "ERROR|" + resp.get("error", "Unknown error") + "\n"

def decode_request(line: str) -> dict:
    """
    Decode a request line into a dictionary.

    Format: "version|code|field1|field2|...|fieldN"
    Example: "1|2|alice|<hashed_password>"
    """
    parts = line.split("|")
    if len(parts) < 2:
        return {"type": "unknown"}  # not enough fields
    version = parts[0]
    try:
        code = int(parts[1])
    except ValueError:
        return {"type": "unknown", "error": "Invalid code"}

    if version != "1":
        return {"type": "unknown", "error": f"Unsupported version: {version}"}

    action = CODE_TO_ACTION.get(code, "unknown")
    fields = parts[2:]  # everything after version and code

    if action == "create_account":
        if len(fields) < 2:
            return {"type": "unknown", "error": "Not enough fields for create_account"}
        return {"type": "create_account", "username": fields[0], "password": fields[1]}
    elif action == "login":
        if len(fields) < 2:
            return {"type": "unknown", "error": "Not enough fields for login"}
        return {"type": "login", "username": fields[0], "password": fields[1]}
    elif action == "list_accounts":
        if len(fields) < 2:
            fields.append("")
        return {"type": "list_accounts", "username": fields[0], "pattern": fields[1]}
    elif action == "send_message":
        if len(fields) < 3:
            return {"type": "unknown", "error": "Not enough fields for send_message"}
        return {"type": "send_message", "from": fields[0], "to": fields[1], "content": fields[2]}
    elif action == "read_new_messages":
        if len(fields) < 2:
            return {"type": "unknown", "error": "Not enough fields for read_new_messages"}
        try:
            count = int(fields[1])
        except ValueError:
            count = 0
        return {"type": "read_new_messages", "username": fields[0], "count": count}
    elif action == "delete_messages":
        if len(fields) < 2:
            return {"type": "unknown", "error": "Not enough fields for delete_messages"}
        return {"type": "delete_messages", "username": fields[0], "message_ids": fields[1]}
    elif action == "delete_account":
        if len(fields) < 1:
            return {"type": "unknown", "error": "No username given for delete_account"}
        return {"type": "delete_account", "username": fields[0]}
    elif action == "list_messages":
        if len(fields) < 1:
            return {"type": "unknown", "error": "No username given for list_messages"}
        return {"type": "list_messages", "username": fields[0]}
    else:
        return {"type": "unknown", "error": "Unrecognized action code"}

def send_response(client_socket, resp: dict):
    resp_str = encode_response(resp)
    data = resp_str.encode("utf-8")

    # Log response size on the same line
    logging.info(f"Outgoing response (size: {len(data)} bytes): {resp_str.strip()}")

    client_socket.sendall(data)

def handle_request(request: dict) -> dict:
    req_type = request.get("type")
    if req_type == "create_account":
        return create_account(request)
    elif req_type == "login":
        return login(request)
    elif req_type == "list_accounts":
        return list_accounts(request)
    elif req_type == "send_message":
        return send_message(request)
    elif req_type == "read_new_messages":
        return read_new_messages(request)
    elif req_type == "delete_messages":
        return delete_messages(request)
    elif req_type == "delete_account":
        return delete_account(request)
    elif req_type == "list_messages":
        return list_messages(request)
    else:
        error_msg = request.get("error", f"Unknown request type: {req_type}")
        return {"status": "error", "error": error_msg}

# ------------------------------------------------------------------------------
# Handler Functions
# ------------------------------------------------------------------------------
def create_account(request: dict) -> dict:
    username = request.get("username")
    password = request.get("password")
    if not username or not password:
        return {"status": "error", "error": "Username or password missing"}
    if username in users_db:
        return {"status": "error", "error": "Username already taken. Use another or log in."}
    users_db[username] = {"password": password, "messages": []}
    return {"status": "ok", "data": [f"Account '{username}' created successfully"]}

def login(request: dict) -> dict:
    username = request.get("username")
    password = request.get("password")
    if not username or not password:
        return {"status": "error", "error": "Username or password missing"}
    if username not in users_db:
        return {"status": "error", "error": "No such user"}
    if users_db[username]["password"] != password:
        return {"status": "error", "error": "Incorrect password"}
    unread_count = sum(1 for m in users_db[username]["messages"] if not m.get("read", False))
    return {"status": "ok", "data": [f"User '{username}' logged in successfully", str(unread_count)]}

def list_accounts(request: dict) -> dict:
    pattern = request.get("pattern", "")
    all_users = list(users_db.keys())
    if pattern == "":
        matches = all_users
    else:
        matches = [u for u in all_users if re.search(pattern, u, re.IGNORECASE)]
    return {"status": "ok", "data": [",".join(matches)]}

def send_message(request: dict) -> dict:
    from_user = request.get("from")
    to_user = request.get("to")
    content = request.get("content")

    if not from_user or not to_user or content is None:
        return {"status": "error", "error": "Missing fields for sending message"}
    if from_user not in users_db:
        return {"status": "error", "error": f"Sender '{from_user}' does not exist"}
    if to_user not in users_db:
        return {"status": "error", "error": f"Recipient '{to_user}' does not exist"}

    # Add a day/hour:minute timestamp, e.g. "02/10 14:37"
    timestamp_str = dt.now().strftime('%m/%d %H:%M')

    users_db[to_user]["messages"].append({
        "from": from_user,
        "content": content,
        "read": False,
        "timestamp": timestamp_str
    })
    return {"status": "ok", "data": ["Message sent successfully"]}

def read_new_messages(request: dict) -> dict:
    username = request.get("username")
    count = request.get("count", 0)
    if not username:
        return {"status": "error", "error": "Username not provided"}
    if username not in users_db:
        return {"status": "error", "error": f"User '{username}' does not exist"}
    all_messages = users_db[username]["messages"]
    unread = [m for m in all_messages if not m.get("read", False)]
    if count <= 0 or count > len(unread):
        count = len(unread)
    selected = unread[:count]
    for m in selected:
        m["read"] = True
    # Include timestamp in the text
    encoded = [f"{m['timestamp']} - From: {m['from']} - {m['content']}" for m in selected]
    return {"status": "ok", "data": [str(len(encoded))] + encoded}

def delete_messages(request: dict) -> dict:
    username = request.get("username")
    msg_ids = request.get("message_ids")
    if not username or not msg_ids:
        return {"status": "error", "error": "Missing fields for delete_messages"}
    if username not in users_db:
        return {"status": "error", "error": f"User '{username}' does not exist"}

    messages = users_db[username]["messages"]
    if msg_ids.lower() == "all":
        users_db[username]["messages"] = []
        return {"status": "ok", "data": ["All messages deleted"]}

    try:
        indices = [int(x.strip()) for x in msg_ids.split(",")]
    except ValueError:
        return {"status": "error", "error": "Invalid message IDs. Must be integers or 'all'."}
    indices = sorted(indices, reverse=True)
    deleted_count = 0
    for i in indices:
        i_minus_1 = i - 1
        if 0 <= i_minus_1 < len(messages):
            del messages[i_minus_1]
            deleted_count += 1
    return {"status": "ok", "data": [f"Deleted {deleted_count} messages."]}

def delete_account(request: dict) -> dict:
    username = request.get("username")
    if not username:
        return {"status": "error", "error": "Username missing for delete_account"}
    if username not in users_db:
        return {"status": "error", "error": f"No such user '{username}'"}
    del users_db[username]
    return {"status": "ok", "data": [f"Account '{username}' deleted."]}

def list_messages(request: dict) -> dict:
    """
    Non-destructively list only messages that have been marked as read.
    Include the timestamp in the text.
    """
    username = request.get("username")
    if not username or username not in users_db:
        return {"status": "error", "error": "Invalid username"}
    messages = [m for m in users_db[username]["messages"] if m.get("read", False)]
    encoded = [f"{m['timestamp']} - From: {m['from']} - {m['content']}" for m in messages]
    return {"status": "ok", "data": [str(len(encoded))] + encoded}

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    # Print to console AND log
    print(f"[+] Server listening on {HOST}:{PORT}")
    logging.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            # Print to console AND log
            print(f"[+] New connection from {client_addr}")
            logging.info(f"[+] New connection from {client_addr}")

            t = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down (KeyboardInterrupt).")
        logging.info("Server shutting down (KeyboardInterrupt).")
    finally:
        server_socket.close()

def handle_client(client_socket, client_address):
    try:
        buffer = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                print(f"[-] Client {client_address} disconnected.")
                logging.info(f"[-] Client {client_address} disconnected.")
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)

                # Log the line size & raw content on the same line
                logging.info(f"Incoming request (size: {len(line)} bytes): {line.decode('utf-8').strip()}")

                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue

                request = decode_request(line_str)
                response = handle_request(request)
                send_response(client_socket, response)

    except ConnectionResetError:
        print(f"[-] Connection reset by {client_address}")
        logging.info(f"[-] Connection reset by {client_address}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_server()
