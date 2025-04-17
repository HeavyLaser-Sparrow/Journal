import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import secrets
import threading
import queue
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import zlib

# --- Speech Recognition Imports ---
try:
    import speech_recognition as sr
except ImportError:
    # Show error later in GUI context if needed, or just print
    print("WARNING: SpeechRecognition library not found. Speak button will be disabled.")
    print("Please install it using: pip install SpeechRecognition PyAudio")
    sr = None

# Constants
KEY_FILE = "key.key"
KEY2_FILE = "key2.key"
DB_FILE = "journal.db"

# Queue for thread-safe GUI updates
default_queue = queue.Queue()

# --- Encryption/Decryption Functions (Copied from previous version) ---

def encrypt_key(key_to_encrypt, key2):
    """Encrypts the given key using key2 with AES-GCM."""
    aesgcm = AESGCM(key2)
    nonce = secrets.token_bytes(12)
    encrypted_key = aesgcm.encrypt(nonce, key_to_encrypt, None)
    return nonce + encrypted_key

def decrypt_key(encrypted_data, key2):
    """Decrypts the given data (nonce + encrypted key) using key2 with AES-GCM."""
    nonce, encrypted_key = encrypted_data[:12], encrypted_data[12:]
    aesgcm = AESGCM(key2)
    return aesgcm.decrypt(nonce, encrypted_key, None)

def encrypt_data(data, key):
    """Encrypts the given data using the provided key with ChaCha20."""
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    compressed_data = zlib.compress(data.encode('utf-8')) # Specify encoding
    return nonce + encryptor.update(compressed_data)

def decrypt_data(encrypted_data, key):
    """Decrypts the given data using the provided key with ChaCha20."""
    nonce, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_bytes = decryptor.update(ciphertext)
        decompressed_data = zlib.decompress(decrypted_bytes)
        return decompressed_data.decode('utf-8') # Specify encoding
    except zlib.error as ze:
        # Using queue for messagebox ensures it runs in the main thread
        default_queue.put((messagebox.showerror, ("Decryption Error", f"Failed to decompress data: {ze}")))
        return None # Indicate failure
    except Exception as e:
        default_queue.put((messagebox.showerror, ("Decryption Error", f"Failed to decrypt data: {e}")))
        return None # Indicate failure

# --- Main Application Class ---

class JournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Journal")
        self.root.geometry("600x450")
        self.root.minsize(400, 350)

        # Speech Recognition Setup
        self.recognizer = sr.Recognizer() if sr else None
        self.is_listening = False

        # Database
        try:
            # isolation_level=None enables autocommit mode
            self.conn = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
            self.cursor = self.conn.cursor()
            self.init_db()
        except sqlite3.Error as e:
             # Use print for critical startup errors before GUI fully runs
             print(f"CRITICAL: Failed to connect or initialize database: {e}")
             messagebox.showerror("Database Error", f"Failed to connect or initialize database: {e}")
             self.root.destroy()
             return

        # Keys
        self.key2 = self.load_key2()
        self.key = self.load_main_key(self.key2)
        if self.key is None:
            # Error message already shown in load_main_key if needed
            print("CRITICAL: Failed to load or decrypt main key. Exiting.")
            if self.conn: self.conn.close() # Close DB if opened
            self.root.destroy()
            return

        # Build GUI
        self.build_gui()

        # Initial data load
        self.load_titles()

        # Start processing queue using root.after
        self.root.after(100, self.process_queue) # Start the queue polling loop

        # Close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def build_gui(self):
        """Creates and lays out the main GUI widgets."""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(3, weight=1) # Content area expands
        self.main_frame.rowconfigure(6, weight=1) # Listbox area expands

        # Title Entry
        ttk.Label(self.main_frame, text="Title:").grid(row=0, column=0, sticky="w", padx=5, pady=(5,0))
        self.title_entry = ttk.Entry(self.main_frame)
        self.title_entry.grid(row=1, column=0, sticky="ew", padx=5, pady=2)

        # Content Text Area
        ttk.Label(self.main_frame, text="Content (Markdown Supported):").grid(row=2, column=0, sticky="w", padx=5, pady=(5,0))
        self.content_text = scrolledtext.ScrolledText(self.main_frame, height=8, wrap=tk.WORD)
        self.content_text.grid(row=3, column=0, sticky="nsew", padx=5, pady=2)

        # Tags Entry
        ttk.Label(self.main_frame, text="Tags (comma-separated):").grid(row=4, column=0, sticky="w", padx=5, pady=(5,0))
        self.tags_entry = ttk.Entry(self.main_frame)
        self.tags_entry.grid(row=5, column=0, sticky="ew", padx=5, pady=2)

        # Entries Listbox and Scrollbar
        self.entries_list = tk.Listbox(self.main_frame, height=6)
        self.entries_list.grid(row=6, column=0, sticky="nsew", padx=5, pady=(5,0))
        scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.entries_list.yview)
        scrollbar.grid(row=6, column=1, sticky="ns", pady=(5,0))
        self.entries_list.config(yscrollcommand=scrollbar.set)
        self.entries_list.bind("<<ListboxSelect>>", self.load_selected_entry)

        # Button Frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=7, column=0, columnspan=2, sticky="ew", padx=5, pady=5) # Span 2 cols
        for i in range(3): # Configure 3 columns for buttons
            self.button_frame.columnconfigure(i, weight=1)

        # Save Button
        ttk.Button(self.button_frame, text="Save (Ctrl+S)", command=self.save_entry).grid(row=0, column=0, sticky="ew", padx=2)

        # Speak Button
        self.speak_button = ttk.Button(
            self.button_frame,
            text="Speak",
            command=self.trigger_speech_thread,
            state=tk.NORMAL if sr else tk.DISABLED # Enable only if sr imported
        )
        self.speak_button.grid(row=0, column=1, sticky="ew", padx=2)
        if not sr:
            self.speak_button.config(text="Speak (Install Libs)") # Update text if disabled

        # Delete Button
        ttk.Button(self.button_frame, text="Delete (Ctrl+D)", command=self.delete_entry).grid(row=0, column=2, sticky="ew", padx=2)

        # Bind shortcuts
        self.bind_shortcuts()

    def process_queue(self):
        """Processes tasks from the default_queue in the main GUI thread."""
        try:
            while True: # Process all pending items
                func, args = default_queue.get_nowait()
                func(*args)
                # task_done is optional if join() isn't used, but doesn't hurt
                # default_queue.task_done()
        except queue.Empty:
            # Queue is empty, do nothing this cycle
            pass
        finally:
            # Schedule the next check
            self.root.after(100, self.process_queue)

    # --- Database and Entry Loading/Saving Methods (Restored & Adapted) ---

    def init_db(self):
        """Initialize the database tables and indexes."""
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS entries (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        date TEXT,
                                        title TEXT UNIQUE,
                                        content BLOB,
                                        tags TEXT)''')
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_title ON entries(title)")
        # No commit needed with isolation_level=None

    def load_titles(self):
        """Load journal entry titles into the listbox."""
        try:
            self.cursor.execute("SELECT title FROM entries ORDER BY date DESC")
            entries = self.cursor.fetchall()
            # Use queue to ensure listbox update happens in main thread safely
            default_queue.put((self._update_titles_list, (entries,)))
        except sqlite3.Error as e:
             default_queue.put((messagebox.showerror, ("Database Error", f"Failed to load titles: {e}")))

    def _update_titles_list(self, entries):
        """Helper to update listbox (runs via queue)."""
        self.entries_list.delete(0, tk.END)
        for entry in entries:
            self.entries_list.insert(tk.END, entry[0])

    def load_selected_entry(self, event=None):
        """Starts thread to load content for the selected listbox item."""
        selected_indices = self.entries_list.curselection()
        if not selected_indices:
            return
        selected_title = self.entries_list.get(selected_indices[0])
        threading.Thread(target=self.load_content_thread, args=(selected_title,), daemon=True).start()

    def load_content_thread(self, title):
        """Loads and decrypts entry content in a background thread."""
        try:
            self.cursor.execute("SELECT content, tags FROM entries WHERE title = ?", (title,))
            result = self.cursor.fetchone()
            if result:
                decrypted_content = decrypt_data(result[0], self.key)
                if decrypted_content is not None: # Check decryption success
                    default_queue.put((self.display_full_entry, (title, decrypted_content, result[1])))
            else:
                 print(f"Warning: Title '{title}' not found during content load.")
                 default_queue.put((self.clear_input_fields, ())) # Clear fields if entry vanished
        except sqlite3.Error as e:
            default_queue.put((messagebox.showerror, ("Database Error", f"Failed to load content for '{title}': {e}")))
        # Decryption errors are handled inside decrypt_data now

    def display_full_entry(self, title, content, tags):
        """Displays loaded entry data in the GUI (runs via queue)."""
        self.title_entry.delete(0, tk.END)
        self.title_entry.insert(0, title)
        self.content_text.delete("1.0", tk.END)
        self.content_text.insert(tk.END, content)
        self.tags_entry.delete(0, tk.END)
        self.tags_entry.insert(0, tags)

    def save_entry(self):
        """Encrypts and saves the current entry data to the database."""
        title = self.title_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        tags = self.tags_entry.get().strip()

        if not title:
            messagebox.showwarning("Input Error", "Title cannot be empty!")
            return
        if not self.key:
             messagebox.showerror("Error", "Encryption key not available. Cannot save.")
             return

        try:
            encrypted_content = encrypt_data(content, self.key)
            self.cursor.execute("SELECT id FROM entries WHERE title = ?", (title,))
            existing_entry = self.cursor.fetchone()
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if existing_entry:
                self.cursor.execute("UPDATE entries SET content = ?, tags = ?, date = ? WHERE title = ?",
                                    (encrypted_content, tags, current_time, title))
            else:
                self.cursor.execute("INSERT INTO entries (date, title, content, tags) VALUES (?, ?, ?, ?)",
                                    (current_time, title, encrypted_content, tags))
            # No commit needed with isolation_level=None

            self.load_titles() # Reload titles immediately
            # Select the saved/updated entry in the list
            default_queue.put((self.select_entry_by_title, (title,))) # Use queue for selection
            # Show success message via queue
            default_queue.put((messagebox.showinfo, ("Success", "Entry saved successfully!")))

        except sqlite3.Error as e:
            default_queue.put((messagebox.showerror, ("Database Error", f"Failed to save entry: {e}")))
        except Exception as e:
             default_queue.put((messagebox.showerror, ("Encryption Error", f"Failed to encrypt or save entry: {e}")))

    def delete_entry(self):
        """Deletes the selected entry from the database."""
        selected_indices = self.entries_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Selection Error", "Please select an entry to delete.")
            return

        selected_title = self.entries_list.get(selected_indices[0])
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to permanently delete '{selected_title}'?", icon='warning'):
            try:
                self.cursor.execute("DELETE FROM entries WHERE title = ?", (selected_title,))
                # No commit needed with isolation_level=None
                self.load_titles()
                self.clear_input_fields() # Clear fields after deletion
                messagebox.showinfo("Success", f"Entry '{selected_title}' deleted.")
            except sqlite3.Error as e:
                 messagebox.showerror("Database Error", f"Failed to delete entry: {e}")

    def clear_input_fields(self, event=None):
        """Clears the title, content, and tags fields."""
        self.title_entry.delete(0, tk.END)
        self.content_text.delete("1.0", tk.END)
        self.tags_entry.delete(0, tk.END)
        self.entries_list.selection_clear(0, tk.END) # Also deselect list item

    def select_entry_by_title(self, title_to_select):
        """Selects an item in the listbox by its title (runs via queue)."""
        try:
            items = self.entries_list.get(0, tk.END)
            if title_to_select in items:
                index = items.index(title_to_select)
                self.entries_list.selection_clear(0, tk.END)
                self.entries_list.selection_set(index)
                self.entries_list.see(index)
                self.entries_list.activate(index)
        except ValueError:
            print(f"Info: Title '{title_to_select}' not found in listbox for selection.")

    # --- Speech Recognition Methods (Adapted from provided snippet) ---

    def trigger_speech_thread(self):
        """Starts the speech recognition thread if possible."""
        if not sr:
            messagebox.showwarning("Setup Needed", "SpeechRecognition library not installed or failed to import.")
            return
        if self.is_listening:
            messagebox.showinfo("Info", "Already listening...")
            return

        self.speak_button.config(state=tk.DISABLED, text="Listening...")
        self.is_listening = True
        # Start the background task
        threading.Thread(target=self.recognize_speech_from_mic, daemon=True).start()

    def recognize_speech_from_mic(self):
        """Listens via microphone and attempts recognition (runs in background thread)."""
        text, error = None, None
        reset_button_text = "Speak" # Default reset text

        if not self.recognizer:
             error = "Recognizer not initialized."
             reset_button_text = "Speak (Error)"
        else:
            try:
                with sr.Microphone() as source:
                    # Optional: Calibrate for ambient noise
                    print("Adjusting for ambient noise...")
                    try:
                        self.recognizer.adjust_for_ambient_noise(source, duration=1)
                        print("Adjusted. Listening...")
                    except Exception as adjust_err:
                         print(f"Warning: Could not adjust for ambient noise: {adjust_err}")
                         # Continue listening anyway

                    # Listen for audio
                    try:
                        audio = self.recognizer.listen(source, timeout=5, phrase_time_limit=15)
                    except sr.WaitTimeoutError:
                        audio = None
                        error = "No speech detected within timeout."
                        print(error) # Console feedback

                # Process audio if captured
                if audio:
                    print("Recognizing...")
                    try:
                        # Attempt recognition using Google
                        text = self.recognizer.recognize_google(audio, language="en-US")
                        print(f"Recognized: {text}")
                    except sr.UnknownValueError:
                        error = "Google Speech Recognition could not understand audio."
                        print(error)
                        reset_button_text = "Speak (Retry)"
                    except sr.RequestError as req_err:
                        error = f"Could not request results from Google service; {req_err}"
                        print(error)
                        reset_button_text = "Speak (API Error)"

            except Exception as mic_err:
                # Catch errors opening microphone etc.
                error = f"Microphone error: {mic_err}"
                print(error)
                reset_button_text = "Speak (Mic Error)"

        # --- Queue GUI updates ---
        # Ensure flag is reset *before* potential modal dialog (messagebox)
        self.is_listening = False

        if text:
            # Queue the append operation and button reset
            default_queue.put((self.append_text_to_content, (text,)))
            default_queue.put((self.reset_speak_button, (reset_button_text,))) # Use default "Speak"
        else:
            # No text, reset button state (potentially with error indication)
            default_queue.put((self.reset_speak_button, (reset_button_text,)))
            # If there was an error, queue the error message display
            if error:
                default_queue.put((messagebox.showerror, ("Speech Recognition Error", error)))


    def append_text_to_content(self, text_to_append):
        """Appends recognized text to the content area (runs via queue)."""
        current_content = self.content_text.get("1.0", tk.END).strip()
        separator = " " if current_content and not current_content.endswith(" ") else ""
        self.content_text.insert(tk.END, separator + text_to_append)
        self.content_text.see(tk.END) # Scroll to make inserted text visible

    def reset_speak_button(self, button_text="Speak"):
        """Resets the speak button state and text (runs via queue)."""
        if sr: # Only enable if library is loaded
             state = tk.NORMAL
        else:
             state = tk.DISABLED
             button_text = "Speak (Install Libs)" # Ensure text reflects state
        self.speak_button.config(state=state, text=button_text)
        # self.is_listening = False # Redundant - reset in recognize_speech_from_mic

    # --- Key Management and Closing Methods (Restored) ---

    def load_key2(self):
        """Loads or generates the secondary key (key2)."""
        try:
            if not os.path.exists(KEY2_FILE):
                key2 = secrets.token_bytes(32) # AES-256
                with open(KEY2_FILE, "wb") as f:
                    f.write(key2)
                try: os.chmod(KEY2_FILE, 0o600)
                except OSError: pass # Ignore chmod errors
                return key2
            else:
                with open(KEY2_FILE, "rb") as f:
                    key2 = f.read()
                if len(key2) != 32:
                    messagebox.showerror("Key Error", f"{KEY2_FILE} is corrupted (invalid length). Please delete it and restart.")
                    return None
                return key2
        except (IOError, OSError) as e:
            messagebox.showerror("File Error", f"Could not read/write {KEY2_FILE}: {e}")
            return None

    def load_main_key(self, current_key2):
        """Loads or generates the main encryption key (key)."""
        if not current_key2: return None

        try:
            if not os.path.exists(KEY_FILE):
                key = secrets.token_bytes(32) # ChaCha20 key size
                encrypted_key_data = encrypt_key(key, current_key2)
                with open(KEY_FILE, "wb") as f:
                    f.write(encrypted_key_data)
                try: os.chmod(KEY_FILE, 0o600)
                except OSError: pass
                return key
            else:
                with open(KEY_FILE, "rb") as f:
                    encrypted_key_data = f.read()
                try:
                    key = decrypt_key(encrypted_key_data, current_key2)
                    if len(key) != 32:
                         messagebox.showerror("Key Error", f"{KEY_FILE} decrypted to an invalid length key. Potential corruption or wrong {KEY2_FILE}.")
                         return None
                    return key
                except Exception as e:
                    messagebox.showerror("Key Decryption Error", f"Failed to decrypt main key using {KEY2_FILE}. Ensure keys are correct or delete {KEY_FILE} (losing old data access).\nError: {e}")
                    return None
        except (IOError, OSError) as e:
            messagebox.showerror("File Error", f"Could not read/write {KEY_FILE}: {e}")
            return None

    def bind_shortcuts(self):
        """Binds keyboard shortcuts for common actions."""
        self.root.bind("<Control-s>", lambda event: self.save_entry())
        self.root.bind("<Control-S>", lambda event: self.save_entry()) # Catch Shift+Ctrl+S
        self.root.bind("<Control-d>", lambda event: self.delete_entry())
        self.root.bind("<Control-D>", lambda event: self.delete_entry()) # Catch Shift+Ctrl+D
        self.root.bind("<Control-n>", lambda event: self.clear_input_fields())
        self.root.bind("<Control-N>", lambda event: self.clear_input_fields()) # Catch Shift+Ctrl+N

    def on_closing(self):
        """Handles window closing: rotates keys, closes DB, destroys window."""
        print("Closing application...")
        try:
            if self.key and self.key2:
                print("Rotating keys...")
                new_key2 = secrets.token_bytes(32)
                encrypted_key_data = encrypt_key(self.key, new_key2)
                with open(KEY_FILE, "wb") as f_key, open(KEY2_FILE, "wb") as f_key2:
                    # Write new main key (encrypted with new key2) first
                    f_key.write(encrypted_key_data)
                    # Then write new key2
                    f_key2.write(new_key2)
                try: # Set permissions
                    os.chmod(KEY_FILE, 0o600)
                    os.chmod(KEY2_FILE, 0o600)
                except OSError: pass
                print("Encryption keys rotated successfully.")
            else:
                 print("Warning: Keys not loaded properly. Cannot rotate keys on exit.")

        except (IOError, OSError) as e:
            print(f"Error rotating keys on exit: {e}")
        except Exception as e:
             print(f"An unexpected error occurred during key rotation: {e}")
        finally:
            print("Closing database connection.")
            if self.conn:
                try: self.conn.close()
                except Exception as e: print(f"Error closing database: {e}")
            print("Destroying root window.")
            self.root.destroy()

# --- Main Execution Block ---
if __name__ == "__main__":
    # Check for library at startup, but let app load anyway
    if sr is None:
         print("INFO: SpeechRecognition library missing, speak feature disabled.")

    root = tk.Tk()
    app = JournalApp(root)
    # Check if app initialization (DB, Keys) was successful before starting mainloop
    if hasattr(app, 'key') and app.key:
        root.mainloop()
    else:
        print("Application initialization failed. Exiting.")
        # Optional: Add a small delay or message window if GUI didn't even start
        # try: root.destroy() # Clean up Tk window if it exists
        # except: pass
