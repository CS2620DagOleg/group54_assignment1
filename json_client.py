import os
import datetime
import logging
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import socket
import sys
import hashlib
import json

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

SERVER_HOST = config["client_connect_host"] 
SERVER_PORT = config["server_port"]

# VERSION for our custom protocol
PROTOCOL_VERSION = "1"

# Maps our high-level request types to numeric codes
TYPE_TO_CODE = {
    "create_account": 1,
    "login": 2,
    "list_accounts": 3,
    "send_message": 4,
    "read_new_messages": 5,
    "delete_messages": 6,
    "delete_account": 7,
    "list_messages": 8
}

# ------------------------------------------------------------------------------
# LOGGING SETUP
# ------------------------------------------------------------------------------
os.makedirs("logs", exist_ok=True)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = os.path.join("logs", f"chat_client_{timestamp}.log")
logging.basicConfig(
    filename=log_filename,
    level=logging.DEBUG,  # change to INFO to reduce verbosity
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logging.info("-------------------------------------------------")
logging.info("Chat Client session started.")
logging.info(f"Logging to file: {log_filename}")

# ------------------------------------------------------------------------------
# HELPER FUNCTIONS FOR CUSTOM PROTOCOL
# ------------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Hash a given password string using SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def encode_request(req: dict) -> str:
    """"
    Conversion to a JSON string.
    """
    return json.dumps(req) + "\n"

def decode_response(resp_str: str) -> dict:
    """"
    conversion into dictionary
    
    """
    try:
        return json.loads(resp_str)
    except json.JSONDecodeError:
        return {"status": "error", "error": "Invalid JSON response"}


def send_request_json(sock: socket.socket, request: dict) -> dict:
    """
    Send a request using JSON and receive the response.
    """
    req_str = encode_request(request)
    data = req_str.encode("utf-8")

    logging.info(f"Sending JSON request (size: {len(data)} bytes): {request}")

    try:
        sock.sendall(data)
    except OSError as e:
        logging.error(f"Error sending data: {e}")
        raise ConnectionError(e)

    response_bytes = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            logging.error("Server closed connection.")
            raise ConnectionError("Server closed connection.")
        response_bytes += chunk
        if b"\n" in response_bytes:
            break

    response_str = response_bytes.decode("utf-8").strip()
    logging.info(f"Received JSON response (size: {len(response_bytes)} bytes): {response_str}")

    return decode_response(response_str)

    


    
    

# ------------------------------------------------------------------------------
# MAIN APPLICATION (GUI)
# ------------------------------------------------------------------------------
class ChatClientApp(tk.Tk):
    """
    Main application class.
    """
    def __init__(self):
        super().__init__()
        self.title("Chat Client")
        self.geometry("400x350")
        logging.info("Initializing ChatClientApp...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            logging.info(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
        except ConnectionRefusedError:
            logging.error(f"Cannot connect to server {SERVER_HOST}:{SERVER_PORT}")
            messagebox.showerror("Error", f"Cannot connect to server {SERVER_HOST}:{SERVER_PORT}")
            sys.exit(1)

        self.current_user = None

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)

        self.frames = {}
        for FrameClass in (StartFrame, MainFrame):
            frame = FrameClass(parent=container, controller=self)
            self.frames[FrameClass] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartFrame)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

    def set_current_user(self, username):
        self.current_user = username

    def get_current_user(self):
        return self.current_user

    def cleanup(self):
        logging.info("Cleaning up and closing socket.")
        try:
            self.sock.close()
        except:
            pass

class StartFrame(tk.Frame):
    """
    Frame for account creation, login, and exit.
    """
    def __init__(self, parent, controller: ChatClientApp):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Welcome to the Chat Client", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Button(self, text="Create Account", width=20, command=self.create_account).pack(pady=5)
        tk.Button(self, text="Login", width=20, command=self.login).pack(pady=5)
        tk.Button(self, text="Exit", width=20, command=self.exit_app).pack(pady=5)

    def create_account(self):
        logging.info("User selected 'Create Account'.")
        username = simpledialog.askstring("Create Account", "Enter a new username:", parent=self)
        if not username:
            return
        password = simpledialog.askstring("Create Account", "Enter a new password:", parent=self, show="*")
        if not password:
            return

        hashed_pass = hash_password(password)
        req = {
            "type": "create_account",
            "username": username,
            "password": hashed_pass
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return

        if response["status"] == "ok":
            messagebox.showinfo("Success", response["data"][0])
        else:
            messagebox.showerror("Error", response["error"])

    def login(self):
        logging.info("User selected 'Login'.")
        username = simpledialog.askstring("Login", "Enter username:", parent=self)
        if not username:
            return
        password = simpledialog.askstring("Login", "Enter password:", parent=self, show="*")
        if not password:
            return

        hashed_pass = hash_password(password)
        req = {
            "type": "login",
            "username": username,
            "password": hashed_pass
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return

        if response["status"] == "ok":
            self.controller.set_current_user(username)
            unread_count = int(response["data"][1]) if len(response["data"]) > 1 else 0
            messagebox.showinfo("Logged In", f"{response['data'][0]}\nUnread messages: {unread_count}")
            self.controller.show_frame(MainFrame)
        else:
            messagebox.showerror("Error", response["error"])

    def exit_app(self):
        self.controller.cleanup()
        self.controller.destroy()

class MainFrame(tk.Frame):
    """
    Main menu frame. Displays "Logged in as:" and buttons for various operations.
    """
    def __init__(self, parent, controller: ChatClientApp):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Main Menu", font=("Arial", 14, "bold")).pack(pady=10)
        self.logged_in_label = tk.Label(self, text="", font=("Arial", 10, "italic"))
        self.logged_in_label.pack(pady=(0, 10))

        tk.Button(self, text="List Accounts", width=20, command=self.list_accounts).pack(pady=5)
        tk.Button(self, text="Send Message", width=20, command=self.send_message).pack(pady=5)
        tk.Button(self, text="Read New Messages", width=20, command=self.read_new_messages).pack(pady=5)
        tk.Button(self, text="Show All Messages", width=20, command=self.show_all_messages).pack(pady=5)
        tk.Button(self, text="Delete My Account", width=20, command=self.delete_account).pack(pady=5)
        tk.Button(self, text="Logout", width=20, command=self.logout).pack(pady=5)

    def tkraise(self, aboveThis=None):
        user = self.controller.get_current_user()
        if user:
            self.logged_in_label.config(text=f"Logged in as: {user}")
        else:
            self.logged_in_label.config(text="Not logged in")
        super().tkraise(aboveThis)

    def list_accounts(self):
        logging.info("User selected 'List Accounts'.")
        pattern = simpledialog.askstring("List Accounts", "Enter wildcard pattern (or leave blank):", parent=self)
        if pattern is None:
            pattern = ""
        req = {
            "type": "list_accounts",
            "username": self.controller.get_current_user(),
            "pattern": pattern
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            accounts_str = response["data"][0] if response["data"] else ""
            accounts = accounts_str.split(",") if accounts_str else []
            msg = "\n".join(accounts) if accounts else "No matching accounts found."
            messagebox.showinfo("Accounts", msg)
        else:
            messagebox.showerror("Error", response["error"])

    def send_message(self):
        logging.info("User selected 'Send Message'.")
        recipient = simpledialog.askstring("Send Message", "Recipient username:", parent=self)
        if not recipient:
            return
        content = simpledialog.askstring("Send Message", "Message content:", parent=self)
        if content is None:
            return
        req = {
            "type": "send_message",
            "from": self.controller.get_current_user(),
            "to": recipient,
            "content": content
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            messagebox.showinfo("Success", response["data"][0])
        else:
            messagebox.showerror("Error", response["error"])

    def read_new_messages(self):
        logging.info("User selected 'Read New Messages'.")
        count_str = simpledialog.askstring("Read New Messages", "How many new messages to read? (leave blank for all)", parent=self)
        if count_str is None or count_str.strip() == "":
            count = 0
        else:
            try:
                count = int(count_str)
            except ValueError:
                count = 0
        req = {
            "type": "read_new_messages",
            "username": self.controller.get_current_user(),
            "count": count
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            num = int(response["data"][0]) if response["data"] else 0
            messages = response["data"][1:] if len(response["data"]) > 1 else []
            if messages:
                display_str = ""
                for idx, msg in enumerate(messages, start=1):
                    display_str += f"{idx}. {msg}\n"
                messagebox.showinfo("New Messages", display_str)
            else:
                messagebox.showinfo("New Messages", "No new messages.")
        else:
            messagebox.showerror("Error", response["error"])

    def show_all_messages(self):
        logging.info("User selected 'Show All Messages'.")
        req = {
            "type": "list_messages",
            "username": self.controller.get_current_user()
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            num = int(response["data"][0]) if response["data"] else 0
            messages = response["data"][1:] if len(response["data"]) > 1 else []
            ShowMessagesWindow(self.controller, messages)
        else:
            messagebox.showerror("Error", response["error"])

    def delete_account(self):
        logging.info("User selected 'Delete My Account'.")
        confirm = messagebox.askyesno(
            "Delete Account",
            "Are you sure you want to delete this account?\nUnread messages will be lost."
        )
        if not confirm:
            return
        req = {
            "type": "delete_account",
            "username": self.controller.get_current_user()
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            messagebox.showinfo("Account Deleted", response["data"][0])
            self.controller.set_current_user(None)
            self.controller.show_frame(StartFrame)
        else:
            messagebox.showerror("Error", response["error"])

    def logout(self):
        logging.info(f"User '{self.controller.get_current_user()}' logging out.")
        self.controller.set_current_user(None)
        self.controller.show_frame(StartFrame)

class ShowMessagesWindow(tk.Toplevel):
    """
    A Toplevel window that displays all read messages (from LISTMSG)
    with a check box for each message and a "Delete Selected" button.
    """
    def __init__(self, controller: ChatClientApp, messages):
        super().__init__()
        self.controller = controller
        self.title("All Messages")
        self.geometry("400x300")
        tk.Label(self, text="All Read Messages", font=("Arial", 12, "bold")).pack(pady=5)
        self.messages = messages
        self.check_vars = []
        self.frame = tk.Frame(self)
        self.frame.pack(fill="both", expand=True)

        for idx, msg in enumerate(self.messages, start=1):
            var = tk.BooleanVar()
            chk = tk.Checkbutton(
                self.frame,
                text=f"{idx}. {msg}",
                variable=var,
                anchor="w",
                justify="left",
                wraplength=350
            )
            chk.pack(fill="x", padx=5, pady=2)
            self.check_vars.append((var, idx))

        tk.Button(self, text="Delete Selected", command=self.delete_selected).pack(pady=5)
        tk.Button(self, text="Close", command=self.destroy).pack(pady=5)

    def delete_selected(self):
        selected = []
        for var, idx in self.check_vars:
            if var.get():
                selected.append(idx)
        if not selected:
            messagebox.showinfo("Info", "No messages selected.")
            return
        ids_str = ",".join(str(i) for i in selected)
        req = {
            "type": "delete_messages",
            "username": self.controller.get_current_user(),
            "message_ids": ids_str
        }
        try:
            response = send_request_json(self.controller.sock, req)
        except ConnectionError as e:
            messagebox.showerror("Error", str(e))
            return
        if response["status"] == "ok":
            messagebox.showinfo("Success", response["data"][0])
            self.destroy()
        else:
            messagebox.showerror("Error", response["error"])

def main():
    logging.info("Starting ChatClientApp main loop.")
    app = ChatClientApp()
    app.protocol("WM_DELETE_WINDOW", app.cleanup)
    app.mainloop()
    logging.info("ChatClientApp has exited.")

if __name__ == "__main__":
    main()
