import json
import os
from tkinter import simpledialog, messagebox, Tk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import base64

# Genererar en krypteringsnyckel från ett huvudlösenord
def generate_key(master_password):
    salt = b"your_salt_here"  # Samma salt som användes i den andra filen
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# Dekrypterar en sträng med Fernet
def decrypt_data(data, key):
    try:
        fernet = Fernet(key)
        return fernet.decrypt(data.encode()).decode()  # Returnerar dekrypterad text
    except Exception as e:
        raise ValueError(f"Dekryptering misslyckades: {str(e)}")

# Laddar och dekrypterar lösenord från JSON-filen
def load_passwords(key):
    folder_name = "saved_passwords"
    file_path = os.path.join(folder_name, "passwords.json")

    if not os.path.exists(file_path):
        raise FileNotFoundError("Ingen sparad lösenordsfil hittades.")

    try:
        # Läs och dekryptera filens innehåll
        with open(file_path, "r") as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data, key)
            passwords = json.loads(decrypted_data)  # Ladda lösenorden som dictionary
            return passwords
    except Exception as e:
        raise ValueError(f"Kunde inte läsa lösenordsfilen: {str(e)}")

# Tkinter GUI för att visa lösenorden
def main():
    root = Tk()
    root.withdraw()  # Dölj huvudfönstret, vi använder bara dialogrutor

    # Hämta huvudlösenordet
    master_password = simpledialog.askstring("Huvudlösenord", "Ange huvudlösenord:", show="*")
    if not master_password:
        messagebox.showwarning("Avbruten", "Inget huvudlösenord angivet.")
        return

    try:
        key = generate_key(master_password)
        passwords = load_passwords(key)

        # Visa lösenorden i en meddelanderuta
        result = "\n".join([f"{desc}: {pwd}" for desc, pwd in passwords.items()])
        messagebox.showinfo("Sparade lösenord", f"Dina sparade lösenord:\n\n{result}")
    except FileNotFoundError as e:
        messagebox.showerror("Fel", str(e))
    except ValueError as e:
        messagebox.showerror("Fel", str(e))
    except Exception as e:
        messagebox.showerror("Fel", f"Ett oväntat fel inträffade: {str(e)}")

if __name__ == "__main__":
    main()