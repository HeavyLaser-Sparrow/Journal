import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import markdown
from cryptography.fernet import Fernet
from datetime import datetime

# Encryption Setup
KEY_FILE = "key.key"

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

encryptor = load_or_create_key()

# Database Setup
def init_db():
    with sqlite3.connect("journal.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS entries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            date TEXT,
                            title TEXT UNIQUE,
                            content BLOB,
                            tags TEXT)''')
        conn.commit()

init_db()

# GUI Setup
class JournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Journal")
        self.root.geometry("600x400")
        self.root.minsize(400, 300)
        
        # Configure resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Title
        ttk.Label(self.main_frame, text="Title:").pack(anchor="w")
        self.title_entry = ttk.Entry(self.main_frame)
        self.title_entry.pack(fill="x", padx=5, pady=2)
        
        # Content
        ttk.Label(self.main_frame, text="Content (Markdown Supported):").pack(anchor="w")
        self.content_text = tk.Text(self.main_frame, height=8)
        self.content_text.pack(fill="both", expand=True, padx=5, pady=2)
        
        # Tags
        ttk.Label(self.main_frame, text="Tags (comma-separated):").pack(anchor="w")
        self.tags_entry = ttk.Entry(self.main_frame)
        self.tags_entry.pack(fill="x", padx=5, pady=2)
        
        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Button(self.button_frame, text="Save", command=self.save_entry).pack(side="left", expand=True)
        ttk.Button(self.button_frame, text="Delete", command=self.delete_entry).pack(side="left", expand=True)
        
        # Entries List
        self.entries_list = tk.Listbox(self.main_frame, height=6)
        self.entries_list.pack(fill="both", expand=True, padx=5, pady=2)
        self.entries_list.bind("<<ListboxSelect>>", self.load_selected_entry)
        
        # Keyboard shortcuts
        self.root.bind("<Control-s>", lambda event: self.save_entry())
        self.root.bind("<Control-BackSpace>", lambda event: self.delete_entry())
        
        self.load_entries()
    
    def encrypt_text(self, text):
        return encryptor.encrypt(text.encode())
    
    def decrypt_text(self, encrypted_text):
        return encryptor.decrypt(encrypted_text).decode()
    
    def save_entry(self):
        title = self.title_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        tags = self.tags_entry.get().strip()
        
        if not title or not content:
            messagebox.showwarning("Warning", "Title and Content cannot be empty!")
            return
        
        encrypted_content = self.encrypt_text(content)
        with sqlite3.connect("journal.db") as conn:
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
    
    def load_selected_entry(self, event):
        selection = self.entries_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        with sqlite3.connect("journal.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title, content, tags FROM entries")
            rows = cursor.fetchall()
        
        title, encrypted_content, tags = rows[index]
        content = self.decrypt_text(encrypted_content)
        
        self.title_entry.delete(0, tk.END)
        self.title_entry.insert(0, title)
        self.content_text.delete("1.0", tk.END)
        self.content_text.insert("1.0", content)
        self.tags_entry.delete(0, tk.END)
        self.tags_entry.insert(0, tags)
    
    def delete_entry(self):
        selection = self.entries_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return
        
        index = selection[0]
        with sqlite3.connect("journal.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM entries")
            rows = cursor.fetchall()
            entry_id = rows[index][0]
            cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            conn.commit()
        
        messagebox.showinfo("Success", "Entry deleted successfully!")
        self.load_entries()
    
    def load_entries(self):
        self.entries_list.delete(0, tk.END)
        with sqlite3.connect("journal.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, date FROM entries")
            rows = cursor.fetchall()
        
        for row in rows:
            self.entries_list.insert(tk.END, f"{row[1]} ({row[2]})")

if __name__ == "__main__":
    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()

