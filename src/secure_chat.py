import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import datetime
import random
import colorsys


class ColorManager:
    def __init__(self):
        self.user_colors = {}  # Maps usernames to their assigned colors
        
    def rgb_to_hex(self, rgb):
        """Convert RGB tuple to hex color code"""
        r, g, b = [int(x * 255) for x in rgb]
        return f"#{r:02x}{g:02x}{b:02x}"
        
    def generate_color(self, username):
        """Generate a color for a new user"""
        if username in self.user_colors:
            return self.user_colors[username]
            
        # If it's a new user, generate a color based on existing ones
        if not self.user_colors:
            # First user gets a vibrant blue
            hue = 210 / 360  # Blue hue
            saturation = 0.8
            lightness = 0.6
        else:
            # Find the largest gap in the hue wheel
            hues = [self._extract_hue(color) for color in self.user_colors.values()]
            hues.sort()
            
            # Add the first hue at the end to check the gap that wraps around
            if hues:
                hues.append(hues[0] + 1.0)
                
                max_gap = 0
                gap_position = 0
                
                for i in range(len(hues) - 1):
                    gap = hues[i+1] - hues[i]
                    if gap > max_gap:
                        max_gap = gap
                        gap_position = i
                
                # Place new color in the middle of the largest gap
                hue = (hues[gap_position] + max_gap / 2) % 1.0
            else:
                # This should never happen since we check for empty user_colors above,
                # but adding as a safety fallback
                hue = random.random()
                
            saturation = 0.7 + random.random() * 0.3  # 70-100% saturation
            lightness = 0.4 + random.random() * 0.35  # 40-75% lightness
            
        # Convert HSL to RGB, then to hex
        rgb = colorsys.hls_to_rgb(hue, lightness, saturation)
        hex_color = self.rgb_to_hex(rgb)
        
        # Store the color for this user
        self.user_colors[username] = hex_color
        return hex_color
        
    def _extract_hue(self, hex_color):
        """Extract the hue value from a hex color"""
        # Convert hex to RGB
        hex_color = hex_color.lstrip('#')
        r, g, b = [int(hex_color[i:i+2], 16) / 255 for i in (0, 2, 4)]
        
        # Convert RGB to HSL and return the hue
        h, l, s = colorsys.rgb_to_hls(r, g, b)
        return h


class SecureChat:
    def __init__(self, root, username, host, port, password):
        self.root = root
        self.username = username
        self.host = host
        self.port = port

        # Setup encryption using the password
        self.setup_encryption(password)
        
        # Initialize color manager
        self.color_manager = ColorManager()
        # Add our own username with a nice color
        self.my_color = self.color_manager.generate_color(self.username)
        
        # Define timestamp color
        self.timestamp_color = "#888888"  # Light gray

        # Setup UI
        self.setup_ui()

        # For file transfer
        self.incoming_files = {}  # To store incoming file chunks

        # Setup network
        self.setup_network()

        # Start listening for messages
        self.listening = True
        threading.Thread(target=self.listen_for_messages).start()

    def setup_encryption(self, password):
        # Generate a key from the password
        password_bytes = password.encode()
        salt = b"secure_chat_salt"  # In a real app, use a random salt and share it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.cipher = Fernet(key)

    def setup_ui(self):
        self.root.title(f"Secure Chat - {self.username}")
        self.root.geometry("600x500")

        # Chat history display
        self.chat_frame = tk.Frame(self.root)
        self.chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.chat_history = scrolledtext.ScrolledText(
            self.chat_frame, wrap=tk.WORD, state=tk.DISABLED
        )
        self.chat_history.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Configure tags for text colors
        self.chat_history.tag_configure("timestamp", foreground=self.timestamp_color)
        self.chat_history.tag_configure("myname", foreground=self.my_color)

        # Message input area
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)

        self.message_input = tk.Entry(self.input_frame)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_input.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            self.input_frame, text="Send", command=self.send_message
        )
        self.send_button.pack(side=tk.RIGHT, padx=5)

        # Add file button
        self.file_button = tk.Button(
            self.input_frame, text="Send File", command=self.select_file
        )
        self.file_button.pack(side=tk.RIGHT, padx=5)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Connected")
        self.status_bar = tk.Label(
            self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Focus on message input
        self.message_input.focus()

    def setup_network(self):
        timestamp = self.get_timestamp()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(("0.0.0.0", self.port))  # Listen on all interfaces

            # Announce presence
            self._send_encrypted_message(
                {"type": "join", "username": self.username, "timestamp": timestamp}
            )

            # Update status
            self.update_status(f"Connected! Listening on port {self.port}")
            self.update_chat_history_system(
                f"Chat started on port {self.port}. Share this port number with your friend.",
                timestamp
            )
            
            # Display a self-join message to show our own color in the system messages
            self.update_chat_history_system(
                f"{self.username} has joined the chat.",
                timestamp,
                highlight_username=self.username
            )
        except OSError as e:
            self.update_status(f"Error: Could not bind to port {self.port}. {str(e)}")
            self.update_chat_history_system(
                f"Failed to start chat. Port {self.port} is unavailable.",
                timestamp
            )

    def update_status(self, status):
        self.status_var.set(status)

    def update_chat_history(self, message, timestamp, sender=None, is_system=False):
        self.chat_history.config(state=tk.NORMAL)
        
        # Insert timestamp with timestamp tag
        timestamp_text = f"[{timestamp}] "
        self.chat_history.insert(tk.END, timestamp_text, "timestamp")
        
        if is_system:
            # Handle system message
            self.chat_history.insert(tk.END, "System: " + message + "\n")
        else:
            # Handle user message with colored username
            if sender == self.username:
                # Our own messages
                self.chat_history.insert(tk.END, "You: ", "myname")
            else:
                # Get or generate color for this user
                user_color = self.color_manager.generate_color(sender)
                # Create a tag for this user if it doesn't exist
                tag_name = f"user_{sender}"
                self.chat_history.tag_configure(tag_name, foreground=user_color)
                self.chat_history.insert(tk.END, f"{sender}: ", tag_name)
            
            # Insert the actual message content
            self.chat_history.insert(tk.END, message + "\n")
        
        self.chat_history.see(tk.END)
        self.chat_history.config(state=tk.DISABLED)

    def update_chat_history_system(self, message, timestamp, highlight_username=None):
        """Convenience method for system messages, with optional username highlighting"""
        self.chat_history.config(state=tk.NORMAL)
        
        # Insert timestamp with timestamp tag
        timestamp_text = f"[{timestamp}] "
        self.chat_history.insert(tk.END, timestamp_text, "timestamp")
        
        # Insert "System: " prefix with a special system tag
        system_tag = "system_text"
        if not system_tag in self.chat_history.tag_names():
            self.chat_history.tag_configure(system_tag, foreground="#009688")  # Teal color for system
        self.chat_history.insert(tk.END, "System: ", system_tag)
        
        # If there's a username to highlight
        if highlight_username:
            # Split the message to isolate the username
            parts = message.split(highlight_username, 1)
            
            # Insert first part of message
            if parts[0]:
                self.chat_history.insert(tk.END, parts[0])
            
            # Insert username with color
            if highlight_username == self.username:
                # Our own username
                self.chat_history.insert(tk.END, highlight_username, "myname")
            else:
                # Get or generate color for this user
                user_color = self.color_manager.generate_color(highlight_username)
                # Create a tag for this user if it doesn't exist
                tag_name = f"user_{highlight_username}"
                self.chat_history.tag_configure(tag_name, foreground=user_color)
                self.chat_history.insert(tk.END, highlight_username, tag_name)
            
            # Insert rest of message
            if len(parts) > 1 and parts[1]:
                self.chat_history.insert(tk.END, parts[1])
        else:
            # Insert regular system message
            self.chat_history.insert(tk.END, message)
        
        # Add newline
        self.chat_history.insert(tk.END, "\n")
        self.chat_history.see(tk.END)
        self.chat_history.config(state=tk.DISABLED)

    def encrypt_message(self, message):
        return self.cipher.encrypt(json.dumps(message).encode()).decode()

    def decrypt_message(self, encrypted_message):
        return json.loads(self.cipher.decrypt(encrypted_message.encode()).decode())

    def _send_encrypted_message(self, message_dict):
        encrypted = self.encrypt_message(message_dict)
        self.socket.sendto(encrypted.encode(), (self.host, self.port))

    def send_message(self, event=None):
        message = self.message_input.get().strip()
        if message:
            # Clear the input field
            self.message_input.delete(0, tk.END)

            # Get timestamp
            timestamp = self.get_timestamp()

            # Send the message
            self._send_encrypted_message(
                {
                    "type": "message",
                    "username": self.username,
                    "content": message,
                    "timestamp": timestamp,
                }
            )

            # Update local chat history
            self.update_chat_history(message, timestamp, self.username)

    def select_file(self):
        # Open file dialog
        file_path = filedialog.askopenfilename(title="Select a file to send")
        if file_path:
            self.send_file(file_path)

    def send_file(self, file_path):
        # Get file info
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Inform the user
        timestamp = self.get_timestamp()
        self.update_chat_history_system(
            f"Sending file '{file_name}' ({file_size} bytes)",
            timestamp
        )

        # Read file contents
        with open(file_path, "rb") as file:
            file_data = base64.b64encode(file.read()).decode("utf-8")

        # Send file info first
        self._send_encrypted_message(
            {
                "type": "file_info",
                "username": self.username,
                "file_name": file_name,
                "file_size": file_size,
                "timestamp": timestamp,
            }
        )

        # Send file data in chunks (to avoid UDP packet size limitations)
        chunk_size = 8192  # Adjust based on your network conditions
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i : i + chunk_size]
            self._send_encrypted_message(
                {
                    "type": "file_chunk",
                    "username": self.username,
                    "file_name": file_name,
                    "chunk_index": i // chunk_size,
                    "total_chunks": (len(file_data) + chunk_size - 1) // chunk_size,
                    "data": chunk,
                    "timestamp": timestamp,
                }
            )

        # Update local chat history
        self.update_chat_history(f"Sent file '{file_name}'", timestamp, self.username)

    def save_received_file(self, file_name):
        # Get file info
        file_info = self.incoming_files[file_name]
        sender = file_info["sender"]

        # Ask user where to save the file
        save_path = filedialog.asksaveasfilename(
            defaultextension=".*",
            initialfile=file_name,
            title=f"Save file from {sender}",
        )

        if save_path:
            # Combine chunks in correct order
            file_data = ""
            for i in range(file_info["total_chunks"]):
                if i in file_info["chunks"]:
                    file_data += file_info["chunks"][i]

            # Decode and save file
            try:
                binary_data = base64.b64decode(file_data)
                with open(save_path, "wb") as file:
                    file.write(binary_data)

                timestamp = self.get_timestamp()
                self.update_chat_history_system(
                    f"File '{file_name}' from {sender} saved to {save_path}",
                    timestamp
                )
            except Exception as e:
                timestamp = self.get_timestamp()
                self.update_chat_history_system(
                    f"Error saving file: {str(e)}",
                    timestamp
                )

        # Clean up
        del self.incoming_files[file_name]

    def get_timestamp(self):
        now = datetime.datetime.now()
        return now.strftime("%H:%M:%S")

    def listen_for_messages(self):
        while self.listening:
            try:
                data, addr = self.socket.recvfrom(4096)
                encrypted_message = data.decode()

                try:
                    message = self.decrypt_message(encrypted_message)

                    if (
                        message["type"] == "message"
                        and message["username"] != self.username
                    ):
                        self.update_chat_history(
                            message["content"],
                            message["timestamp"],
                            message["username"]
                        )

                    elif (
                        message["type"] == "join"
                        and message["username"] != self.username
                    ):
                        self.update_chat_history_system(
                            f"{message['username']} has joined the chat.",
                            message["timestamp"],
                            highlight_username=message['username']
                        )

                    # Handle file info message
                    elif (
                        message["type"] == "file_info"
                        and message["username"] != self.username
                    ):
                        file_name = message["file_name"]
                        file_size = message["file_size"]
                        self.incoming_files[file_name] = {
                            "size": file_size,
                            "chunks": {},
                            "total_chunks": 0,
                            "sender": message["username"],
                        }
                        self.update_chat_history_system(
                            f"{message['username']} is sending file '{file_name}' ({file_size} bytes)",
                            message["timestamp"]
                        )

                    # Handle file chunk message
                    elif (
                        message["type"] == "file_chunk"
                        and message["username"] != self.username
                    ):
                        file_name = message["file_name"]
                        if file_name in self.incoming_files:
                            chunk_index = message["chunk_index"]
                            self.incoming_files[file_name]["chunks"][chunk_index] = (
                                message["data"]
                            )
                            self.incoming_files[file_name]["total_chunks"] = message[
                                "total_chunks"
                            ]

                            # Check if we've received all chunks
                            if (
                                len(self.incoming_files[file_name]["chunks"])
                                == self.incoming_files[file_name]["total_chunks"]
                            ):
                                self.save_received_file(file_name)
                                
                    # Handle leave message
                    elif (
                        message["type"] == "leave"
                        and message["username"] != self.username
                    ):
                        self.update_chat_history_system(
                            f"{message['username']} has left the chat.",
                            message["timestamp"]
                        )

                except Exception as e:
                    # Failed to decrypt - wrong password or invalid message
                    pass

            except Exception as e:
                if self.listening:
                    self.update_status(f"Error: {str(e)}")

    def close(self):
        self.listening = False
        timestamp = self.get_timestamp()
        self._send_encrypted_message(
            {"type": "leave", "username": self.username, "timestamp": timestamp}
        )
        self.socket.close()


def find_available_port(start_port=5555, max_attempts=10):
    """Find an available port starting from start_port"""
    for attempt in range(max_attempts):
        try:
            test_port = start_port + attempt
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.bind(("0.0.0.0", test_port))
            test_socket.close()
            return test_port
        except OSError:
            continue
    return None


def main():
    # Get configuration
    print("=== Secure Chat Setup ===")
    username = input("Enter your username: ")
    friend_ip = input("Enter your friend's IP address: ")

    # Port selection with auto option
    port_input = input(
        "Enter port number (e.g. 5555) or press Enter for automatic selection: "
    )
    if port_input.strip():
        port = int(port_input)
    else:
        port = find_available_port()
        if port:
            print(f"Automatically selected port: {port}")
        else:
            print("Could not find available port. Please try a manual port number.")
            port = int(input("Enter port number: "))

    password = input("Enter shared secret password: ")

    # Start the application
    root = tk.Tk()
    app = SecureChat(root, username, friend_ip, port, password)

    def on_closing():
        app.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()