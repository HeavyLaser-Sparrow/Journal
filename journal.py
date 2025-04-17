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
import numpy as np
import simpleaudio as sa
import time

# --- Speech Recognition Imports ---
try:
    import speech_recognition as sr
except ImportError:
    print("WARNING: SpeechRecognition library not found. Speak button will be disabled.")
    print("Please install it using: pip install SpeechRecognition PyAudio")
    sr = None

# Constants
KEY_FILE = "key.key"
KEY2_FILE = "key2.key"
DB_FILE = "journal.db"

# Thread-safe GUI queue
default_queue = queue.Queue()

# --- Beep Generation ---
def play_beep(frequency=440, duration=0.2, sample_rate=44100):
    """Generate and play a simple sine-wave beep."""
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = np.sin(frequency * 2 * np.pi * t)
    audio = (tone * 32767).astype(np.int16)
    play_obj = sa.play_buffer(audio, 1, 2, sample_rate)
    play_obj.wait_done()

# --- Encryption / Decryption ---
def encrypt_key(key_to_encrypt, key2):
    aesgcm = AESGCM(key2)
    nonce = secrets.token_bytes(12)
    encrypted_key = aesgcm.encrypt(nonce, key_to_encrypt, None)
    return nonce + encrypted_key

def decrypt_key(encrypted_data, key2):
    nonce, encrypted_key = encrypted_data[:12], encrypted_data[12:]
    aesgcm = AESGCM(key2)
    return aesgcm.decrypt(nonce, encrypted_key, None)

def encrypt_data(data, key):
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    compressed = zlib.compress(data.encode('utf-8'))
    return nonce + encryptor.update(compressed)

def decrypt_data(encrypted, key):
    nonce, ciphertext = encrypted[:16], encrypted[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted = decryptor.update(ciphertext)
        return zlib.decompress(decrypted).decode('utf-8')
    except Exception as e:
        default_queue.put((messagebox.showerror, ("Decryption Error", str(e))))
        return None

class JournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Journal")
        self.root.geometry("600x450")
        self.root.minsize(400, 350)

        # Speech recognizer
        self.recognizer = sr.Recognizer() if sr else None
        self.is_listening = False

        # Database
        try:
            self.conn = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
            self.cursor = self.conn.cursor()
            self.init_db()
        except Exception as e:
            messagebox.showerror("Database Error", f"{e}")
            self.root.destroy()
            return

        # Keys
        self.key2 = self.load_key2()
        self.key = self.load_main_key(self.key2)
        if self.key is None:
            self.root.destroy()
            return

        # Build GUI
        self.build_gui()
        self.load_titles()
        self.root.after(100, self.process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def build_gui(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)

        ttk.Label(frame, text="Title:").grid(row=0, column=0, sticky="w")
        self.title_entry = ttk.Entry(frame)
        self.title_entry.grid(row=1, column=0, sticky="ew")

        ttk.Label(frame, text="Content (Markdown Supported):").grid(row=2, column=0, sticky="w")
        self.content_text = scrolledtext.ScrolledText(frame, height=8)
        self.content_text.grid(row=3, column=0, sticky="nsew")

        ttk.Label(frame, text="Tags (comma-separated):").grid(row=4, column=0, sticky="w")
        self.tags_entry = ttk.Entry(frame)
        self.tags_entry.grid(row=5, column=0, sticky="ew")

        self.entries_list = tk.Listbox(frame, height=6)
        self.entries_list.grid(row=6, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frame, command=self.entries_list.yview)
        sb.grid(row=6, column=1, sticky="ns")
        self.entries_list.config(yscrollcommand=sb.set)
        self.entries_list.bind("<<ListboxSelect>>", self.load_selected_entry)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=7, column=0, columnspan=2, sticky="ew", pady=5)
        for i in range(3): btn_frame.columnconfigure(i, weight=1)

        ttk.Button(btn_frame, text="Save (Ctrl+S)", command=self.save_entry).grid(row=0, column=0, sticky="ew")
        self.speak_button = ttk.Button(btn_frame, text="Speak", command=self.trigger_speech_thread,
                                       state=tk.NORMAL if sr else tk.DISABLED)
        self.speak_button.grid(row=0, column=1, sticky="ew")
        if not sr: self.speak_button.config(text="Speak (Install Libs)")
        ttk.Button(btn_frame, text="Delete (Ctrl+D)", command=self.delete_entry).grid(row=0, column=2, sticky="ew")

        self.bind_shortcuts()

    def process_queue(self):
        try:
            while True:
                func, args = default_queue.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def init_db(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, date TEXT, title TEXT UNIQUE, content BLOB, tags TEXT)''')
        self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_title ON entries(title)")

    def load_titles(self):
        try:
            self.cursor.execute("SELECT title FROM entries ORDER BY date DESC")
            entries = self.cursor.fetchall()
            default_queue.put((self._update_titles_list, (entries,)))
        except Exception as e:
            default_queue.put((messagebox.showerror, ("DB Error", str(e))))

    def _update_titles_list(self, entries):
        self.entries_list.delete(0, tk.END)
        for (t,) in entries: self.entries_list.insert(tk.END, t)

    def load_selected_entry(self, event=None):
        sel = self.entries_list.curselection()
        if not sel: return
        title = self.entries_list.get(sel[0])
        threading.Thread(target=self.load_content_thread, args=(title,), daemon=True).start()

    def load_content_thread(self, title):
        try:
            self.cursor.execute("SELECT content, tags FROM entries WHERE title=?", (title,))
            row = self.cursor.fetchone()
            if row:
                text = decrypt_data(row[0], self.key)
                if text is not None:
                    default_queue.put((self.display_full_entry, (title, text, row[1])))
        except Exception as e:
            default_queue.put((messagebox.showerror, ("DB Error", str(e))))

    def display_full_entry(self, title, content, tags):
        self.title_entry.delete(0, tk.END); self.title_entry.insert(0, title)
        self.content_text.delete("1.0", tk.END); self.content_text.insert(tk.END, content)
        self.tags_entry.delete(0, tk.END); self.tags_entry.insert(0, tags)

    def save_entry(self):
        title = self.title_entry.get().strip()
        if not title:
            messagebox.showwarning("Input Error","Title cannot be empty!"); return
        content = self.content_text.get("1.0", tk.END).strip()
        tags = self.tags_entry.get().strip()
        enc = encrypt_data(content, self.key)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.cursor.execute("SELECT id FROM entries WHERE title=?", (title,))
            if self.cursor.fetchone():
                self.cursor.execute("UPDATE entries SET content=?,tags=?,date=? WHERE title=?", (enc, tags, now, title))
            else:
                self.cursor.execute("INSERT INTO entries(date,title,content,tags) VALUES(?,?,?,?)", (now, title, enc, tags))
            self.load_titles(); default_queue.put((messagebox.showinfo,("Saved","Entry saved.")))
        except Exception as e:
            messagebox.showerror("DB Error", str(e))

    def delete_entry(self):
        sel = self.entries_list.curselection()
        if not sel: messagebox.showwarning("Select","Choose entry to delete"); return
        title = self.entries_list.get(sel[0])
        if messagebox.askyesno("Confirm","Delete '%s'?"%title):
            try:
                self.cursor.execute("DELETE FROM entries WHERE title=?", (title,))
                self.load_titles(); self.clear_input_fields()
            except Exception as e:
                messagebox.showerror("DB Error", str(e))

    def clear_input_fields(self, event=None):
        self.title_entry.delete(0, tk.END); self.content_text.delete("1.0", tk.END); self.tags_entry.delete(0, tk.END)
        self.entries_list.selection_clear(0, tk.END)

    def select_entry_by_title(self, t):
        items = self.entries_list.get(0, tk.END)
        if t in items:
            i = items.index(t); self.entries_list.selection_set(i); self.entries_list.see(i)

    def trigger_speech_thread(self):
        if not sr:
            messagebox.showwarning("Setup","Install SpeechRecognition"); return
        if self.is_listening:
            messagebox.showinfo("Info","Already listening"); return
        threading.Thread(target=self._prepare_and_listen, daemon=True).start()

    def _prepare_and_listen(self):
        default_queue.put((messagebox.showinfo,("Ready","Please speak after the beep.")))
        time.sleep(0.4); play_beep(); time.sleep(0.6)
        default_queue.put((self.begin_listening,()))

    def begin_listening(self):
        self.speak_button.config(state=tk.DISABLED,text="Listening...")
        self.is_listening=True
        threading.Thread(target=self.recognize_speech_from_mic, daemon=True).start()

    def recognize_speech_from_mic(self):
        text, error = None, None
        reset = "Speak"
        if not self.recognizer:
            error="No recognizer"; reset="Error"
        else:
            try:
                with sr.Microphone() as src:
                    self.recognizer.adjust_for_ambient_noise(src, duration=1)
                    audio=self.recognizer.listen(src, timeout=5, phrase_time_limit=15)
                    text=self.recognizer.recognize_google(audio)
            except sr.WaitTimeoutError:
                error="Timeout"
            except sr.UnknownValueError:
                error="Unrecognized"
            except Exception as e:
                error=str(e)
        self.is_listening=False
        if text:
            default_queue.put((self.append_text_to_content,(text,)))
        else:
            default_queue.put((messagebox.showerror,("Error", error)))
        default_queue.put((self.reset_speak_button,(reset,)))

    def append_text_to_content(self, txt):
        cur=self.content_text.get("1.0",tk.END).strip()
        sep=" " if cur and not cur.endswith(" ") else ""
        self.content_text.insert(tk.END,sep+txt); self.content_text.see(tk.END)

    def reset_speak_button(self, txt="Speak"):
        st=tk.NORMAL if sr else tk.DISABLED
        self.speak_button.config(state=st,text=txt)

    def load_key2(self):
        try:
            if not os.path.exists(KEY2_FILE):
                k=secrets.token_bytes(32)
                with open(KEY2_FILE,'wb') as f: f.write(k); os.chmod(KEY2_FILE,0o600)
                return k
            else:
                with open(KEY2_FILE,'rb') as f: k=f.read()
                return k if len(k)==32 else None
        except:
            return None

    def load_main_key(self, k2):
        if not k2: return None
        if not os.path.exists(KEY_FILE):
            key=secrets.token_bytes(32)
            enc=encrypt_key(key,k2)
            with open(KEY_FILE,'wb') as f: f.write(enc); os.chmod(KEY_FILE,0o600)
            return key
        try:
            with open(KEY_FILE,'rb') as f: data=f.read()
            key=decrypt_key(data,k2)
            return key if len(key)==32 else None
        except:
            return None

    def bind_shortcuts(self):
        self.root.bind("<Control-s>",lambda e: self.save_entry())
        self.root.bind("<Control-d>",lambda e: self.delete_entry())
        self.root.bind("<Control-n>",lambda e: self.clear_input_fields())

    def on_closing(self):
        if self.key and self.key2:
            nk2=secrets.token_bytes(32)
            enc=encrypt_key(self.key,nk2)
            with open(KEY_FILE,'wb') as f: f.write(enc)
            with open(KEY2_FILE,'wb') as f: f.write(nk2)
        if self.conn: self.conn.close()
        self.root.destroy()

if __name__=='__main__':
    root=tk.Tk()
    app=JournalApp(root)
    if hasattr(app,'key') and app.key:
        root.mainloop()
    else:
        print("Init failed")

