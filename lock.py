# encrypted_lock_app_v7.py
import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox, ttk
import os, json, base64, secrets, zlib, subprocess, zipfile, tarfile, mimetypes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

MAGIC = b"LOCKv7"

# --- Crypto ---
def derive_key(password, salt, iterations=200_000):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=iterations, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_manifest(manifest, password):
    data = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    compressed = zlib.compress(data, level=9)
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aes.encrypt(nonce, compressed, None)
    return MAGIC + salt + nonce + ciphertext

def decrypt_manifest(filebytes, password):
    if not filebytes.startswith(MAGIC):
        raise ValueError("Not a valid .lock file")
    offset = len(MAGIC)
    salt, nonce, ciphertext = filebytes[offset:offset+16], filebytes[offset+16:offset+28], filebytes[offset+28:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    compressed = aes.decrypt(nonce, ciphertext, None)
    data = zlib.decompress(compressed)
    return json.loads(data.decode("utf-8"))

def lock_file_permissions(path):
    try:
        username = os.getlogin()
        subprocess.run(f'icacls "{path}" /inheritance:r /grant {username}:(F)', shell=True)
    except: pass

# --- Storage ---
class FileStore:
    def __init__(self):
        self.files = {}  # path: bytes
        self.comment = ""

    def add_file(self, path, content):
        self.files[path] = content

    def delete_file(self, path):
        self.files.pop(path, None)

    def get_manifest(self):
        return {"files":[{"path":p,"content_b64":base64.b64encode(c).decode()} for p,c in self.files.items()],
                "comment":self.comment}

    def load_manifest(self, manifest):
        self.files = {f["path"]:base64.b64decode(f["content_b64"]) for f in manifest.get("files", [])}
        self.comment = manifest.get("comment","")

# --- GUI App ---
class LockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(".lock Nested Archive 1.0")
        self.geometry("1000x600")
        self.store = FileStore()
        self.build_ui()

    def build_ui(self):
        left = ttk.Frame(self)
        left.pack(side="left", fill="y")
        ttk.Label(left,text="Files").pack(padx=6,pady=(6,0))
        self.file_list = tk.Listbox(left,width=50)
        self.file_list.pack(padx=6,pady=6,fill="y",expand=True)
        self.file_list.bind("<<ListboxSelect>>",self.on_select)

        ttk.Button(left,text="Add Folder",command=self.add_folder).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Add Files",command=self.add_files).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Add Archive",command=self.add_archive).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Delete File",command=self.delete_file).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Open File",command=self.open_file).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Import .lock",command=self.import_lock).pack(fill="x",padx=6,pady=2)
        ttk.Button(left,text="Export .lock",command=self.export_lock).pack(fill="x",padx=6,pady=2)

        right = ttk.Frame(self)
        right.pack(side="right",fill="both",expand=True)
        topbar = ttk.Frame(right)
        topbar.pack(fill="x")
        self.filename_label = ttk.Label(topbar,text="No file selected",font=("Segoe UI",10,"bold"))
        self.filename_label.pack(side="left",padx=6,pady=6)
        ttk.Button(topbar,text="Save Text",command=self.save_current).pack(side="right", padx=6, pady=6)
        ttk.Button(topbar,text="Open Externally",command=self.open_externally).pack(side="right", padx=6, pady=6)

        self.text = tk.Text(right,wrap="none",undo=True)
        self.text.pack(fill="both",expand=True,padx=6,pady=(0,6))
        self.status = ttk.Label(self,text="Ready",anchor="w")
        self.status.pack(fill="x",side="bottom")

    def _refresh_list(self):
        self.file_list.delete(0,tk.END)
        for p in sorted(self.store.files.keys()):
            self.file_list.insert(tk.END,p)

    # --- Add Folder ---
    def add_folder(self):
        folder = filedialog.askdirectory()
        if not folder: return
        base = os.path.basename(folder)
        for root, _, files in os.walk(folder):
            for f in files:
                full = os.path.join(root,f)
                rel = os.path.relpath(full, folder)
                try:
                    with open(full,"rb") as fh:
                        self.store.add_file(os.path.join(base,rel),fh.read())
                except: pass
        self._refresh_list()
        self.status.config(text=f"Added folder {base}")

    # --- Add Individual Files ---
    def add_files(self):
        paths = filedialog.askopenfilenames()
        for p in paths:
            with open(p,"rb") as fh:
                self.store.add_file(os.path.basename(p),fh.read())
        self._refresh_list()
        self.status.config(text="Added files")

    # --- Add Archive as virtual folder ---
    def add_archive(self):
        paths = filedialog.askopenfilenames(filetypes=[("Archives","*.zip *.tar *.tar.gz"),("All files","*.*")])
        for p in paths:
            name = os.path.basename(p)
            try:
                if p.endswith(".zip"):
                    with zipfile.ZipFile(p,"r") as zf:
                        for info in zf.infolist():
                            if info.is_dir(): continue
                            self.store.add_file(os.path.join(name,info.filename), zf.read(info))
                elif p.endswith(".tar") or p.endswith(".tar.gz") or p.endswith(".tgz"):
                    mode = "r:gz" if p.endswith(".gz") else "r"
                    with tarfile.open(p,mode) as tf:
                        for member in tf.getmembers():
                            if not member.isfile(): continue
                            fileobj = tf.extractfile(member)
                            if fileobj:
                                self.store.add_file(os.path.join(name,member.name), fileobj.read())
                else:
                    with open(p,"rb") as fh:
                        self.store.add_file(name,fh.read())
            except Exception as e:
                messagebox.showwarning("Archive Error", f"{name}: {e}")
        self._refresh_list()
        self.status.config(text="Added archive(s) as folders")

    # --- File Actions ---
    def on_select(self,event):
        sel = self.file_list.curselection()
        if not sel: return
        path = self.file_list.get(sel[0])
        content = self.store.files[path]
        try:
            text = content.decode("utf-8")
            self.text.delete("1.0",tk.END)
            self.text.insert("1.0", text)
        except:
            self.text.delete("1.0",tk.END)
            self.text.insert("1.0","<binary file - editing not supported>")
        self.filename_label.config(text=path)
        self.status.config(text=f"Loaded {path}")

    def save_current(self):
        sel = self.file_list.curselection()
        if not sel: return
        path = self.file_list.get(sel[0])
        try:
            content = self.text.get("1.0","end-1c").encode("utf-8")
            self.store.files[path] = content
            self.status.config(text=f"Saved {path}")
        except:
            self.status.config(text="Cannot save binary file")

    def delete_file(self):
        sel = self.file_list.curselection()
        if not sel: return
        path = self.file_list.get(sel[0])
        self.store.delete_file(path)
        self._refresh_list()
        self.text.delete("1.0",tk.END)
        self.filename_label.config(text="No file selected")
        self.status.config(text=f"Deleted {path}")

    # --- Open in editor (text) ---
    def open_file(self):
        sel = self.file_list.curselection()
        if not sel: return
        path = self.file_list.get(sel[0])
        content = self.store.files[path]

        try:
            text = content.decode("utf-8")
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", text)
            self.filename_label.config(text=path)
            self.status.config(text=f"Loaded text {path}")
        except:
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0","<binary file - editing not supported>")
            self.filename_label.config(text=path)
            self.status.config(text=f"Binary file loaded (cannot edit)")

    # --- Open Externally button ---
    def open_externally(self):
        sel = self.file_list.curselection()
        if not sel:
            self.status.config(text="No file selected")
            return
        path = self.file_list.get(sel[0])
        content = self.store.files[path]

        tmp_path = os.path.join(os.path.expanduser("~"), f"temp_{os.path.basename(path)}")
        with open(tmp_path,"wb") as f:
            f.write(content)

        mime,_ = mimetypes.guess_type(tmp_path)
        try:
            if os.name=="nt":
                if mime:
                    if mime.startswith("image"):
                        os.system(f'mspaint "{tmp_path}"')
                    elif mime.startswith("video") or mime.startswith("audio"):
                        os.startfile(tmp_path)
                    else:
                        os.startfile(tmp_path)
                else:
                    os.startfile(tmp_path)
            else:
                subprocess.run(["xdg-open", tmp_path])
            self.status.config(text=f"Opened {path} externally")
        except Exception as e:
            self.status.config(text=f"Failed to open {path}: {e}")

    # --- Import/Export ---
    def export_lock(self):
        if not self.store.files: return
        pw = simpledialog.askstring("Password","Enter password",show="*")
        if not pw: return
        comment = simpledialog.askstring("Comment","Optional comment")
        self.store.comment = comment or ""
        data = encrypt_manifest(self.store.get_manifest(),pw)
        path = filedialog.asksaveasfilename(defaultextension=".lock",filetypes=[("Encrypted lock","*.lock")])
        if not path: return
        with open(path,"wb") as f: f.write(data)
        lock_file_permissions(path)
        self.status.config(text=f"Exported {os.path.basename(path)}")

    def import_lock(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted lock","*.lock")])
        if not path: return
        with open(path,"rb") as f: b=f.read()
        pw = simpledialog.askstring("Password","Enter password",show="*")
        if pw is None: return
        try: manifest = decrypt_manifest(b,pw)
        except Exception as e: messagebox.showerror("Decryption failed", str(e)); return
        self.store.load_manifest(manifest)
        self._refresh_list()
        if self.store.comment: messagebox.showinfo("Comment", self.store.comment)
        self.status.config(text=f"Imported {os.path.basename(path)}")

if __name__=="__main__":
    app = LockApp()
    app.mainloop()
