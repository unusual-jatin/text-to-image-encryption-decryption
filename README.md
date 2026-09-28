# text-to-image-encryption-decryption

A Python-based desktop application that securely encrypts secret text and hides it invisibly inside image files. 

I built this project to explore the intersection of **Cryptography** and **Steganography**. Instead of just hiding data in an image (which is easily extractable), this tool first encrypts the text using military-grade encryption, and *then* weaves that cipher into the pixel data of a cover image. To the naked eye, the image looks completely normal.

---

## ✨ Features

* **Authenticated Encryption:** Uses **AES-256-GCM** to ensure the data is not only encrypted but also protected against tampering.
* **Strong Key Derivation:** User passwords are run through **PBKDF2HMAC** (SHA-256 with 600,000 iterations) with a randomized salt to defend against brute-force attacks.
* **LSB Steganography:** Hides the encrypted payload by altering the Least Significant Bit (LSB) of the RGB channels in the image. This changes pixel colors by a maximum of 1/255th, making the alteration visually undetectable.
* **Clean GUI:** A lightweight, native graphical interface built with `Tkinter` for easy encryption and decryption.
* **Data Integrity Checks:** The app verifies magic bytes (`SIMG1`) before attempting decryption to prevent crashes on invalid files.

---

## 🛠️ Tech Stack

* **Python 3**
* **Cryptography:** The `cryptography.hazmat` library for AES-GCM and PBKDF2 implementation.
* **Pillow (PIL):** Used for iterating through and manipulating raw pixel data.
* **Tkinter:** Standard GUI framework for the desktop interface.

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/unusual-jatin/secret-image-encryptor.git](https://github.com/unusual-jatin/secret-image-encryptor.git)
   cd secret-image-encryptor


Install the required dependencies:
Make sure you have Python installed, then run:


pip install cryptography pillow

Run the application

python main.py
💡 How to Use

To Encrypt:
Open the Encrypt tab.

Type your secret message.

Enter a strong password.

Select a cover image (JPEG, PNG, BMP).

Click Encrypt and Save. The app will output a PNG file.

To Decrypt:
Open the Decrypt tab.

Select the encrypted PNG file.

Enter the exact password used during encryption.

Click Decrypt to reveal the hidden text.

⚠️ Important Note on File Sharing:
Because this relies on pixel-perfect data, compression destroys the hidden payload. If you send the encrypted image via WhatsApp, Instagram, or iMessage, the app will compress it to a JPEG, destroying the hidden bits. To share encrypted images, send them as uncompressed files (e.g., via Email, Google Drive, or Discord).

🧠 Under the Hood (How it works)
When you hit encrypt, the application does the following:

Generates a random 16-byte salt and 12-byte nonce.

Derives a 32-byte cryptographic key from your password using PBKDF2.

Encrypts your text using AES-GCM.

Packages the data as: Magic Bytes (SIMG1) + Salt + Nonce + Ciphertext.

Converts the entire package into a stream of binary bits.

Iterates through the cover image's pixels, swapping the 8th bit (Least Significant Bit) of every Red, Green, and Blue channel with a bit from the payload stream until the data is fully embedded.

