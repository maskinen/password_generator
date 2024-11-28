import random
import string
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import base64
import json
import os

# Genererar en krypteringsnyckel från ett huvudlösenord med PBKDF2HMAC
def generate_key(master_password):
    salt = b"your_salt_here"  # Salt används för att göra nyckeln unik, ska vara samma varje gång
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),  # Hash-algoritm som används
        length=32,           # Längd på den genererade nyckeln
        salt=salt,           # Förutbestämt salt
        iterations=100_000,  # Antal iterationer för att öka säkerheten
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))  # Genererar nyckeln
    return key

# Krypterar en sträng med hjälp av Fernet
def encrypt_data(data, key):
    try:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()  # Returnerar krypterad text
    except Exception as e:
        raise ValueError(f"Kryptering misslyckades: {str(e)}")

# Dekrypterar en sträng med hjälp av Fernet
def decrypt_data(data, key):
    try:
        fernet = Fernet(key)
        return fernet.decrypt(data.encode()).decode()  # Returnerar dekrypterad text
    except Exception as e:
        raise ValueError(f"Dekryptering misslyckades: {str(e)}")

# Genererar ett slumpmässigt lösenord
def generate_password():
    total = string.ascii_letters + string.digits + string.punctuation
    length = 16  # Lösenordets längd
    return "".join(random.sample(total, length))

# Sparar ett lösenord krypterat i en JSON-fil
def save_password(password, key):
    # Kontrollera och skapa mappen om den inte redan finns
    folder_name = "saved_passwords"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    
    # Filväg där lösenord lagras
    file_path = os.path.join(folder_name, "passwords.json")
    
    try:
        # Läs existerande data från filen om den finns
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, "r") as file:
                encrypted_data = file.read()
                decrypted_data = decrypt_data(encrypted_data, key)  # Dekrypterar filens innehåll
                data = json.loads(decrypted_data)  # Laddar data som ett dictionary
        else:
            data = {}
        
        # Be användaren om en beskrivning av lösenordet
        description = simpledialog.askstring("Spara lösenord", "Beskrivning:")
        if not description:
            messagebox.showwarning("Avbruten", "Ingen beskrivning angiven.")  # Varna om ingen beskrivning ges
            return
        
        # Lägg till lösenordet till dictionaryt
        data[description] = password

        # Kryptera och skriv data till filen
        encrypted_data = encrypt_data(json.dumps(data), key)
        with open(file_path, "w") as file:
            file.write(encrypted_data)
        
        messagebox.showinfo("Sparat", f"Lösenordet har sparats i {file_path}!")
    except Exception as e:
        messagebox.showerror("Fel", f"Kunde inte spara lösenordet: {str(e)}")

# Hämta huvudlösenord från användaren via en dialog
def get_master_password():
    return simpledialog.askstring("Huvudlösenord", "Ange huvudlösenord:", show="*")

# Tkinter GUI för applikationen
def main():
    # Genererar ett lösenord och visar det i textfältet
    def on_generate():
        password = generate_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)

    # Sparar lösenordet som visas i textfältet
    def on_save():
        master_password = get_master_password()
        if not master_password:
            messagebox.showwarning("Avbruten", "Ingen huvudlösenord angivet.")  # Om inget huvudlösenord anges
            return
        
        key = generate_key(master_password)
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Ingen data", "Inget lösenord att spara.")  # Om inget lösenord genererats
            return
        save_password(password, key)

    # Skapa huvudfönstret
    root = tk.Tk()
    root.title("Lösenordsgenerator")
    
    # Layout för GUI-komponenter
    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack()

    tk.Label(frame, text="Genererat lösenord:").grid(row=0, column=0, pady=5)
    password_entry = tk.Entry(frame, width=30)
    password_entry.grid(row=0, column=1, pady=5)

    generate_button = tk.Button(frame, text="Generera lösenord", command=on_generate)
    generate_button.grid(row=1, column=0, pady=5)

    save_button = tk.Button(frame, text="Spara lösenord", command=on_save)
    save_button.grid(row=1, column=1, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()