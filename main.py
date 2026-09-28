import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_TITLE = "Secret Image Encryptor"
MAGIC = b"SIMG1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(message: str, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt_message(payload: bytes, password: str) -> str:
    minimum = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16
    if len(payload) < minimum or payload[:len(MAGIC)] != MAGIC:
        raise ValueError("This image does not contain valid encrypted data.")
    offset = len(MAGIC)
    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = payload[offset:]
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc:
        raise ValueError("Wrong password or corrupted encrypted data.") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("The decrypted data is not valid UTF-8 text.") from exc


def bytes_to_bits(data: bytes):
    for byte in data:
        for bit in range(7, -1, -1):
            yield (byte >> bit) & 1


def bits_to_bytes(bits):
    out = bytearray()
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | bit
        count += 1
        if count == 8:
            out.append(value)
            value = 0
            count = 0
    if count:
        raise ValueError("Corrupted hidden data.")
    return bytes(out)


def hide_payload(source_path: str, output_path: str, payload: bytes) -> None:
    image = Image.open(source_path).convert("RGB")
    pixels = list(image.getdata())
    packed = struct.pack(">Q", len(payload)) + payload
    bits = list(bytes_to_bits(packed))
    capacity = len(pixels) * 3
    if len(bits) > capacity:
        max_payload = max(0, capacity // 8 - 8)
        raise ValueError(
            "The selected image is too small.\n"
            f"Approximate maximum hidden data: {max_payload:,} bytes.\n"
            f"Required hidden data: {len(payload):,} bytes."
        )
    new_pixels = []
    bit_index = 0
    for r, g, b in pixels:
        channels = [r, g, b]
        for i in range(3):
            if bit_index < len(bits):
                channels[i] = (channels[i] & 0xFE) | bits[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))
    out = Image.new("RGB", image.size)
    out.putdata(new_pixels)
    out.save(output_path, "PNG", optimize=False)


def extract_payload(image_path: str) -> bytes:
    image = Image.open(image_path).convert("RGB")
    bits = []
    for r, g, b in image.getdata():
        bits.extend((r & 1, g & 1, b & 1))
    if len(bits) < 64:
        raise ValueError("The image is too small to contain encrypted data.")
    length = struct.unpack(">Q", bits_to_bytes(bits[:64]))[0]
    max_available = (len(bits) - 64) // 8
    if length > max_available:
        raise ValueError("No valid hidden payload was found in this image.")
    return bits_to_bytes(bits[64:64 + length * 8])


class SecretImageEncryptor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("940x720")
        self.minsize(820, 640)
        self.configure(bg="#f3f5f7")
        self.selected_cover = tk.StringVar()
        self.decrypt_image = tk.StringVar()
        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("App.TFrame", background="#f3f5f7")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Title.TLabel", background="#f3f5f7", font=("Segoe UI", 22, "bold"))
        style.configure("SubTitle.TLabel", background="#f3f5f7", foreground="#5b6470", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background="#ffffff", font=("Segoe UI", 14, "bold"))
        style.configure("Field.TLabel", background="#ffffff", foreground="#364152", font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", background="#ffffff", foreground="#6b7280", font=("Segoe UI", 9))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(16, 9))
        style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(14, 8))
        style.configure("Status.TLabel", background="#f3f5f7", foreground="#55606f", font=("Segoe UI", 9))

    def _build_ui(self):
        outer = ttk.Frame(self, style="App.TFrame", padding=26)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="🔐 Secret Image Encryptor", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Encrypt text with AES-256-GCM and hide the encrypted data inside a PNG image.", style="SubTitle.TLabel").pack(anchor="w", pady=(4, 18))
        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        encrypt_tab = ttk.Frame(notebook, padding=18)
        decrypt_tab = ttk.Frame(notebook, padding=18)
        notebook.add(encrypt_tab, text="  Encrypt  ")
        notebook.add(decrypt_tab, text="  Decrypt  ")
        self._build_encrypt_tab(encrypt_tab)
        self._build_decrypt_tab(decrypt_tab)
        ttk.Label(outer, text="Security note: the password is never stored in the image. Share it separately. Use PNG; resizing or JPEG recompression can destroy hidden data.", style="Status.TLabel", wraplength=850, justify="left").pack(anchor="w", pady=(12, 0))

    def _make_card(self, parent):
        card = ttk.Frame(parent, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)
        return card

    def _build_encrypt_tab(self, parent):
        card = self._make_card(parent)
        ttk.Label(card, text="Create an encrypted image", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 16))
        ttk.Label(card, text="Secret text", style="Field.TLabel").pack(anchor="w")
        self.message_box = ScrolledText(card, height=8, wrap="word", font=("Consolas", 10), relief="solid", borderwidth=1)
        self.message_box.pack(fill="x", expand=False, pady=(6, 12))
        ttk.Label(card, text="Password", style="Field.TLabel").pack(anchor="w")
        self.encrypt_password = ttk.Entry(card, show="•")
        self.encrypt_password.pack(anchor="w", fill="x", pady=(6, 4))
        ttk.Label(card, text="Use a strong password. The recipient will need this exact password to decrypt.", style="Hint.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Label(card, text="Cover image", style="Field.TLabel").pack(anchor="w")
        cover_row = ttk.Frame(card, style="Card.TFrame")
        cover_row.pack(fill="x", pady=(6, 12))
        ttk.Entry(cover_row, textvariable=self.selected_cover, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(cover_row, text="Choose image…", style="Secondary.TButton", command=self.choose_cover_image).pack(side="left", padx=(8, 0))
        ttk.Label(card, text="A larger image can hold more text. The output is always saved as PNG.", style="Hint.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Button(card, text="🔒  Encrypt and Save PNG", style="Primary.TButton", command=self.encrypt_clicked).pack(anchor="e")

    def _build_decrypt_tab(self, parent):
        card = self._make_card(parent)
        ttk.Label(card, text="Open an encrypted image", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 16))
        ttk.Label(card, text="Encrypted PNG", style="Field.TLabel").pack(anchor="w")
        image_row = ttk.Frame(card, style="Card.TFrame")
        image_row.pack(fill="x", pady=(6, 14))
        ttk.Entry(image_row, textvariable=self.decrypt_image, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(image_row, text="Choose PNG…", style="Secondary.TButton", command=self.choose_decrypt_image).pack(side="left", padx=(8, 0))
        ttk.Label(card, text="Password", style="Field.TLabel").pack(anchor="w")
        self.decrypt_password = ttk.Entry(card, show="•")
        self.decrypt_password.pack(fill="x", pady=(6, 14))
        ttk.Button(card, text="🔓  Decrypt", style="Primary.TButton", command=self.decrypt_clicked).pack(anchor="e")
        ttk.Label(card, text="Decrypted text", style="Field.TLabel").pack(anchor="w", pady=(22, 6))
        self.decrypted_box = ScrolledText(card, height=10, wrap="word", font=("Consolas", 10), relief="solid", borderwidth=1)
        self.decrypted_box.pack(fill="both", expand=True)
        button_row = ttk.Frame(card, style="Card.TFrame")
        button_row.pack(fill="x", pady=(10, 0))
        ttk.Button(button_row, text="Copy text", style="Secondary.TButton", command=self.copy_decrypted).pack(side="right")
        ttk.Button(button_row, text="Clear", style="Secondary.TButton", command=self.clear_decrypted).pack(side="right", padx=(0, 8))

    def choose_cover_image(self):
        path = filedialog.askopenfilename(title="Choose a cover image", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("PNG files", "*.png"), ("All files", "*.*")])
        if path:
            self.selected_cover.set(path)

    def choose_decrypt_image(self):
        path = filedialog.askopenfilename(title="Choose an encrypted PNG", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if path:
            self.decrypt_image.set(path)

    def encrypt_clicked(self):
        message = self.message_box.get("1.0", "end-1c").strip()
        password = self.encrypt_password.get()
        cover = self.selected_cover.get().strip()
        if not message:
            messagebox.showwarning(APP_TITLE, "Enter some text to encrypt.")
            return
        if not password:
            messagebox.showwarning(APP_TITLE, "Enter a password.")
            return
        if not cover:
            messagebox.showwarning(APP_TITLE, "Choose a cover image.")
            return
        try:
            Image.open(cover).verify()
        except Exception:
            messagebox.showerror(APP_TITLE, "The selected image could not be opened.")
            return
        output = filedialog.asksaveasfilename(title="Save encrypted image", defaultextension=".png", initialfile="secret.png", filetypes=[("PNG files", "*.png")])
        if not output:
            return
        try:
            payload = encrypt_message(message, password)
            hide_payload(cover, output, payload)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.encrypt_password.delete(0, "end")
        messagebox.showinfo(APP_TITLE, f"Encryption successful.\n\nSaved to:\n{output}\n\nSend this PNG to the recipient and share the password separately.")

    def decrypt_clicked(self):
        image_path = self.decrypt_image.get().strip()
        password = self.decrypt_password.get()
        if not image_path:
            messagebox.showwarning(APP_TITLE, "Choose an encrypted PNG.")
            return
        if not password:
            messagebox.showwarning(APP_TITLE, "Enter the password.")
            return
        try:
            payload = extract_payload(image_path)
            text = decrypt_message(payload, password)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.decrypted_box.delete("1.0", "end")
        self.decrypted_box.insert("1.0", text)

    def copy_decrypted(self):
        text = self.decrypted_box.get("1.0", "end-1c")
        if not text:
            messagebox.showinfo(APP_TITLE, "There is no decrypted text to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        messagebox.showinfo(APP_TITLE, "Decrypted text copied to the clipboard.")

    def clear_decrypted(self):
        self.decrypted_box.delete("1.0", "end")
        self.decrypt_password.delete(0, "end")


if __name__ == "__main__":
    SecretImageEncryptor().mainloop()
