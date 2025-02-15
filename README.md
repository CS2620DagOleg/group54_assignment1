# Chat Application Documentation

This document provides an **a guide** for our Chat Client/Server application in Python. The application supports **two wire protocol implementations**:

1. A **Custom Wire Protocol** (a delimited text format).  
2. A **JSON-Based Wire Protocol** (messages serialized/deserialized with JSON).

Both protocols offer **the same features**. The **custom wire protocol** is more compact (thus more bandwidth-efficient), while the **JSON** variant is easier to parse and debug.

---

## Table of Contents
1. [Overview](#overview)  
2. [Features](#features)  
3. [Architecture and Flow](#architecture-and-flow)  
4. [Installation and Setup](#installation-and-setup)  
5. [Usage Examples](#usage-examples)  
6. [Comparing Custom Wire Protocol vs. JSON](#comparing-custom-wire-protocol-vs-json)  
7. [Testing (Including JSON Testing)](#testing-including-json-testing)  
8. [Troubleshooting](#troubleshooting)  
9. [Potential Improvements](#potential-improvements)  
10. [License](#license)  

---

## 1. Overview

This **Chat Application** consists of:

- A **Server** that:
  - Manages **user accounts** (username, hashed password).
  - Stores and retrieves **messages** (unread/read).
  - Receives and responds to client requests (create account, login, etc.).

- A **Client** that:
  - Uses **Tkinter** to provide a **graphical user interface**.
  - Lets users **create accounts**, **log in**, **send messages** to other users, **read** or **list** messages, **delete** messages, and **delete** accounts.
  - Communicates with the server either via **custom delimited text** or **JSON** (depending on which version of the code you use).

### Main Goals
- Demonstrate a multi-threaded Python server that can handle multiple clients.
- Show how a client-side GUI can interact with a server using **TCP**.
- Illustrate two **wire protocol** approaches for the same functionality.

---

## 2. Features

1. **Account Management**  
   - Create new user accounts (username + hashed password).  
   - Log in, receiving a count of unread messages.  
   - Delete an account (removing all data for that user).  

2. **Messaging**  
   - **Send** a text message from one user to another (the recipient must exist).  
   - **Read** unread messages (marks them as read).  
   - **List** all previously read messages.  
   - **Delete** individual messages (by ID) or delete **all** messages at once.  

3. **Listing Accounts**  
   - The client can request a list of all user accounts, optionally filtered by a wildcard (regex) pattern (e.g. `^A` for users starting with “A”).  

4. **Logging**  
   - Both client and server create timestamped log files in a `logs/` directory for debugging and auditing.

## 3. Architecture and Flow

1. **Server**:
   - Listens on a specified **TCP port** (default `4999`).  
   - Each new **client connection** is handled in a **separate thread**.  
   - Uses an in-memory dictionary (`users_db`) to track user passwords and messages.
   - Logs major events (connections, requests, etc.) to a file in `logs/`.

2. **Client**:
   - Written in **Python/Tkinter** to provide a user-friendly GUI.  
   - Connects to the server’s IP/port.  
   - Sends **requests** (create_account, login, send_message, etc.) to the server.  
   - Receives and decodes **responses** (OK/error, plus any data).  
   - Maintains a minimal state (the currently logged-in user).

3. **Data Flow**:
   - **Client** forms a request (dictionary) and transforms it into a wire format:
     - **Custom Protocol**: `"version|code|field1|field2|...\n"`  
     - **JSON**: a JSON string (e.g. `{"type": "login", "username": "alice", ...}\n`)  
   - **Server** reads the data until `\n` (newline), decodes it, and dispatches to the appropriate handler function.
   - The **handler** updates or reads data from `users_db`, then returns a response dictionary, which is encoded and sent back to the client.

4. **In-Memory Database** (`users_db`):
   ```python
   users_db = {
     "alice": {
       "password": "<hashed_password>",
       "messages": [
         {
           "from": "bob",
           "content": "Hello",
           "read": False,
           "timestamp": "02/10 14:37"
         },
         ...
       ]
     },
     "bob": {...},
     ...
   }
   ```
   - Data resets if the server restarts, since no persistent storage is used.

---

## 4. Installation and Setup

1. **Requirements**:
   - Python 3.7+  
   - Tkinter library (often preinstalled on Windows/macOS; on some Linux distros, you may install it via `sudo apt-get install python3-tk`).

2. **Obtaining the Code**:
   - Place the server script (e.g. `custom_server.py`) and client script (e.g. `custom_client.py`) in the same directory (or structured as you like).
   - A `logs/` directory is automatically created for storing log files.

3. **Running the Server**:
   ```bash
   python custom_server.py
   ```
   - By default, it listens on `0.0.0.0:4999`.  
   - To change the port or host, edit `server_port` and `client_connect_host` in the `config.json`.

4. **Running the Client**:
   ```bash
   python custom_client.py
   ```
   - A GUI window opens.  
   - If your server is on a different IP or port, adjust inside of `config.json`.  
   - The client logs to `logs/chat_client_<timestamp>.log`.

---

## 5. Usage Examples

Below are common steps a user might do in the GUI:

1. **Create Account**  
   - Press “Create Account,” enter a username/password.  
   - If successful, an “Account created successfully” message is shown.

2. **Login**  
   - Press “Login,” enter existing credentials.  
   - You’ll see how many unread messages you have upon successful login.

3. **Send Message**  
   - Choose a recipient and type the content.  
   - If the recipient exists, the server stores the message in their unread queue.

4. **Read New Messages**  
   - Choose how many unread messages to read (0 or blank means all).  
   - They become marked as read.

5. **Show All Messages**  
   - Displays read messages in a separate window, each with a checkbox to **delete**.

6. **Delete Account**  
   - Prompts for confirmation.  
   - The server removes the user and all associated messages.

7. **List Accounts**  
   - Enter a regex pattern or leave blank to see all.  
   - Useful for discovering other users in the system.

---

## 6. Comparing Custom Wire Protocol vs. JSON

### Custom Wire Protocol
- **Message Format**:  
  `version|code|field1|field2|...|fieldN\n`
  - Example for creating an account: `1|1|alice|<hashed_password>\n`
- **Pros**:  
  - More compact (fewer extra characters).  
  - Potentially faster to parse and less bandwidth usage.  
- **Cons**:  
  - Must do manual parsing (split on `|`), handle edge cases.  
  - Harder to extend with nested structures.

### JSON Wire Protocol
- **Message Format**:  
  A line of valid JSON, e.g.:  
  `{"type": "login", "username": "alice", "password": "somehash"}\n`
- **Pros**:  
  - Parsing is straightforward with `json.loads()`.  
  - Familiar to many developers, flexible for nested data.  
- **Cons**:  
  - Includes extra characters (`{}`, `":`, etc.), making transmissions bigger.  
  - Slight overhead in JSON serialization/deserialization.

**Note**: Both protocols produce identical functionality; choose based on your preference for performance vs. extensibility.

---

## 7. Testing 

### Overview
- We use **Python’s `unittest`** module to test both client- and server-side logic.
- **Server Tests**: Verify that request handlers (`create_account`, `login`, `send_message`, etc.) correctly modify or retrieve data from `users_db`.  
- **Client Tests**: Often **mock** the socket to confirm that requests and responses are encoded/decoded properly.

### JSON Testing
- In **JSON** mode, we test:
  - **`decode_request`**: Ensures valid JSON is parsed, and invalid JSON triggers an error.
  - **`encode_response`**: Ensures the final JSON string includes a newline and can be re-parsed.
  - **Handler functions**: For example, a test that calls `login(request)` with a correct password checks the returned `"status"` is `"ok"`.
- Example test steps (pseudocode):
  ```python
  def test_decode_request_valid_json(self):
      line_str = '{"type": "login", "username": "alice"}'
      result = decode_request(line_str)
      assert result["type"] == "login"
      assert result["username"] == "alice"
  ```
- Additional tests handle **edge cases** (e.g., missing commas, nonexistent fields).

### Why This Matters
- JSON tests confirm the system gracefully handles valid/invalid JSON, and the server’s business logic remains correct when using JSON as the wire format.

---

## 8. Troubleshooting

1. **Cannot connect to server**  
   - Ensure the **server** is running and that **IP/port** match your `custom_client.py` settings.  
   - Check firewall or antivirus that may block incoming connections.

2. **Server closes connection immediately**  
   - Possibly a crash on the server side. Check the server logs in `logs/chat_server_<timestamp>.log` for exceptions.

3. **Data not saved**  
   - The data is in-memory only. If you restart the server, all accounts/messages vanish. This is **by design** for demonstration.

4. **Regex not matching**  
   - The `list_accounts` function uses Python’s `re.search`; ensure your pattern is correct (or try a simpler pattern).

---

## 9. Potential Improvements

- **Add Persistent Storage**  
  - Use SQLite, PostgreSQL, or another database so users/accounts/messages remain after server restarts.
- **Enhance Security**  
  - Use TLS/SSL for an encrypted connection.  
  - Store salted password hashes (e.g., `bcrypt`) for stronger protection.
- **Scalability**  
  - Switch to an async framework (`asyncio` or `Twisted`) if you expect high concurrency.
- **Features**  
  - Group chats, attachments, or message search.  
  - Real-time notifications or user presence tracking.

---
---

**End of Documentation**  
