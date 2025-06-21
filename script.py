import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file:\n{e}")
        return None

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        hash_result = calculate_sha256(file_path)
        if hash_result:
            hash_text.delete(1.0, tk.END)
            hash_text.insert(tk.END, hash_result)

def verify_hash():
    input_hash = hash_input.get().strip()
    file_hash = hash_text.get(1.0, tk.END).strip()
    if input_hash == file_hash:
        messagebox.showinfo("Result", "✅ Hashes match!")
    else:
        messagebox.showwarning("Result", "❌ Hashes do not match.")

# GUI setup
app = tk.Tk()
app.title("SHA-256 File Hash Checker")
app.geometry("500x300")

tk.Button(app, text="Select File", command=select_file).pack(pady=10)

hash_text = tk.Text(app, height=4, wrap="word")
hash_text.pack(fill="x", padx=10)

tk.Label(app, text="Enter hash to compare:").pack(pady=5)
hash_input = tk.Entry(app, width=70)
hash_input.pack(pady=5)

tk.Button(app, text="Verify Hash", command=verify_hash).pack(pady=10)

app.mainloop()
