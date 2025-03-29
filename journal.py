import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import markdown
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# File paths
KEY_FILE = "key.key"
KEY2_FILE = "key2.key"
DB_FILE = "journal.db"

# Load or generate key2
if not os.path.exists(KEY2_FILE):
    key2 = secrets.token_bytes(32)  # AES-256 key
    with open(KEY2_FILE, "wb") as f:
        f.write(key2)
else:
    with open(KEY2_FILE, "rb") as f:
        key2 = f.read()

def encrypt_key_file():
    try:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        aesgcm = AESGCM(key2)
        nonce = secrets.token_bytes(12)
        encrypted_key = aesgcm.encrypt(nonce, key, None)
        with open(KEY_FILE, "wb") as f:
            f.write(nonce + encrypted_key)
    except Exception as e:
        messagebox.showerror("Error", f"Error encrypting key file: {e}")

def decrypt_key_file():
    try:
        with open(KEY_FILE, "rb") as f:
            data = f.read()
        nonce, encrypted_key = data[:12], data[12:]
        aesgcm = AESGCM(key2)
        return aesgcm.decrypt(nonce, encrypted_key, None)
    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting key file: {e}")
        return None

# Load or create main encryption key
if not os.path.exists(KEY_FILE):
    key = secrets.token_bytes(32)  # ChaCha20 key
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    encrypt_key_file()
else:
    key = decrypt_key_file()
    if key is None:
        exit()

def encrypt_data(data):
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(data.encode())

def decrypt_data(encrypted_data):
    nonce, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext).decode()
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt data: {e}")
        return ""

# Database setup
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS entries (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        date TEXT,
                                        title TEXT UNIQUE,
                                        content BLOB,
                                        tags TEXT)''')
        conn.commit()

init_db()

# GUI
class JournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Journal")
        self.root.geometry("600x400")
        self.root.minsize(400, 300)

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(self.main_frame, text="Title:").pack(anchor="w")
        self.title_entry = ttk.Entry(self.main_frame)
        self.title_entry.pack(fill="x", padx=5, pady=2)

        ttk.Label(self.main_frame, text="Content (Markdown Supported):").pack(anchor="w")
        self.content_text = tk.Text(self.main_frame, height=8)
        self.content_text.pack(fill="both", expand=True, padx=5, pady=2)

        ttk.Label(self.main_frame, text="Tags (comma-separated):").pack(anchor="w")
        self.tags_entry = ttk.Entry(self.main_frame)
        self.tags_entry.pack(fill="x", padx=5, pady=2)

        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill="x", padx=5, pady=2)

        ttk.Button(self.button_frame, text="Save", command=self.save_entry).pack(side="left", expand=True)
        ttk.Button(self.button_frame, text="Delete", command=self.delete_entry).pack(side="left", expand=True)

        self.entries_list = tk.Listbox(self.main_frame, height=6)
        self.entries_list.pack(fill="both", expand=True, padx=5, pady=2)
        self.entries_list.bind("<<ListboxSelect>>", self.load_selected_entry)

        self.load_entries()
        self.bind_shortcuts()

    def bind_shortcuts(self):
        self.root.bind("<Control-s>", lambda event: self.save_entry())
        self.root.bind("<Control-d>", lambda event: self.delete_entry())
        self.root.bind("<Control-n>", lambda event: self.clear_input_fields())

    def save_entry(self):
        title = self.title_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        tags = self.tags_entry.get().strip()
        
        if not title or not content:
            messagebox.showwarning("Warning", "Title and Content cannot be empty!")
            return

        encrypted_content = encrypt_data(content)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM entries WHERE title = ?", (title,))
            existing_entry = cursor.fetchone()

            if existing_entry:
                cursor.execute("UPDATE entries SET content = ?, tags = ? WHERE title = ?", 
                               (encrypted_content, tags, title))
            else:
                date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("INSERT INTO entries (date, title, content, tags) VALUES (?, ?, ?, ?)", 
                               (date, title, encrypted_content, tags))
            conn.commit()

        self.clear_input_fields()
        messagebox.showinfo("Success", "Entry saved successfully!")
        self.load_entries()

    def clear_input_fields(self):
        self.title_entry.delete(0, tk.END)
        self.content_text.delete("1.0", tk.END)
        self.tags_entry.delete(0, tk.END)

    def load_entries(self):
        self.entries_list.delete(0, tk.END)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title FROM entries")
            entries = cursor.fetchall()
            for entry in entries:
                self.entries_list.insert(tk.END, entry[0])

    def load_selected_entry(self, event):
        selected_index = self.entries_list.curselection()
        if not selected_index:
            return

        selected_title = self.entries_list.get(selected_index[0])
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT content, tags FROM entries WHERE title = ?", (selected_title,))
            entry = cursor.fetchone()
            if entry:
                decrypted_content = decrypt_data(entry[0])
                self.title_entry.delete(0, tk.END)
                self.title_entry.insert(0, selected_title)
                self.content_text.delete("1.0", tk.END)
                self.content_text.insert(tk.END, decrypted_content)
                self.tags_entry.delete(0, tk.END)
                self.tags_entry.insert(0, entry[1])

    def delete_entry(self):
        selected_index = self.entries_list.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return

        selected_title = self.entries_list.get(selected_index[0])
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete '{selected_title}'?"):
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM entries WHERE title = ?", (selected_title,))
                conn.commit()
            self.clear_input_fields()
            self.load_entries()
            messagebox.showinfo("Success", "Entry deleted successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()
