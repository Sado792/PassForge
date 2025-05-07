# -*- coding: utf-8 -*- # Good practice for encoding

import tkinter as tk
from tkinter import messagebox, simpledialog, font as tkFont # Import font module
import random
import string
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

master_password = ""
# --- Core Functions (Unchanged) ---

# Funzione per generare la password
def genera_password(lunghezza=12, uso_maiuscole=True, uso_minuscole=True, uso_numeri=True, uso_simboli=True):
    caratteri_possibili = ''
    if uso_maiuscole:
        caratteri_possibili += string.ascii_uppercase
    if uso_minuscole:
        caratteri_possibili += string.ascii_lowercase
    if uso_numeri:
        caratteri_possibili += string.digits
    if uso_simboli:
        caratteri_possibili += string.punctuation

    if not caratteri_possibili:
        raise ValueError("Devi selezionare almeno un tipo di carattere.")

    if not isinstance(lunghezza, int) or lunghezza <= 0:
        raise ValueError("La lunghezza deve essere un numero intero positivo.")

    try:
        import secrets
        password = ''.join(secrets.choice(caratteri_possibili) for _ in range(lunghezza))
    except ImportError:
        print("Warning: 'secrets' module not found, using 'random'.")
        password = ''.join(random.choice(caratteri_possibili) for _ in range(lunghezza))

    return password




# Funzione per derivare una chiave dalla master password
def derivare_chiave(master_password):
    # Utilizziamo PBKDF2 con HMAC e SHA-256
    salt = b"salt_value_123"  # Dovresti usare un salt unico per ogni utente/finestra
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=32,  # Lunghezza della chiave
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Funzione per cifrare i dati
def cifra_dati(data, master_password):
    key = derivare_chiave(master_password)
    # Crea un iv (vector di inizializzazione)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding per assicurarsi che i dati siano un multiplo di 16
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(json.dumps(data).encode()) + padder.finalize()

    # Cifra i dati
    cipher_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Restituisci iv e dati cifrati (entrambi in base64)
    return base64.b64encode(iv + cipher_data).decode()

# Funzione per decifrare i dati
def decifra_dati(cifra_data, master_password):
    key = derivare_chiave(master_password)
    data = base64.b64decode(cifra_data)

    iv = data[:16]  # I primi 16 byte sono l'IV
    cipher_data = data[16:]  # Il resto sono i dati cifrati

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decifra i dati
    decrypted_data = decryptor.update(cipher_data) + decryptor.finalize()

    # Rimuovi il padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return json.loads(unpadded_data.decode())

    master_password = simpledialog.askstring("Password", "Inserisci la tua master password:")
    if not master_password:
        messagebox.showerror("Errore", "Password non fornita.")
        return {}

# Funzione per caricare i dati dal file JSON
def carica_dati():

    file_name = "passwords.json"
    if os.path.exists(file_name):
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                content = f.read()
                if not content:
                    return {}
                return decifra_dati(content, master_password)
        except (json.JSONDecodeError, IOError) as e:
            messagebox.showerror("Errore Lettura", f"Impossibile leggere o decodificare {file_name}.\n{e}")
            return {}
    else:
        return {}

# Funzione per salvare i dati nel file JSON
def salva_dati(data):
    
    file_name = "passwords.json"
    try:
        encrypted_data = cifra_dati(data, master_password)
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
#            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except IOError as e:
        messagebox.showerror("Errore Scrittura", f"Impossibile salvare i dati in {file_name}.\n{e}")
        return False
    except Exception as e:
         messagebox.showerror("Errore Inaspettato", f"Errore durante il salvataggio dei dati.\n{e}")
         return False


# --- GUI Handler Functions ---

def on_generare_password():
    global root
    try:
        try:
            lunghezza_str = entry_lunghezza.get()
            if not lunghezza_str.isdigit():
                 raise ValueError("La lunghezza deve essere un numero intero.")
            lunghezza = int(lunghezza_str)
        except ValueError as e:
             messagebox.showerror("Input Non Valido", str(e), parent=root)
             return

        uso_maiuscole = var_maiuscole.get()
        uso_minuscole = var_minuscole.get()
        uso_numeri = var_numeri.get()
        uso_simboli = var_simboli.get()

        password = genera_password(lunghezza, uso_maiuscole, uso_minuscole, uso_numeri, uso_simboli)

        entry_password.config(state=tk.NORMAL)
        entry_password.delete(0, tk.END)
        entry_password.insert(0, password)
        entry_password.config(state='readonly')

        try:
            root.clipboard_clear()
            root.clipboard_append(password)
            show_temp_message("Password copiata negli appunti!")
        except tk.TclError:
             messagebox.showwarning("Appunti", "Impossibile accedere agli appunti.", parent=root)

    except ValueError as e:
        messagebox.showerror("Errore Generazione", str(e), parent=root)
    except Exception as e:
        messagebox.showerror("Errore Inaspettato", f"Si è verificato un errore:\n{e}", parent=root)


def on_salvare_password():
    global root
    nome_servizio = entry_servizio.get().strip()
    nome_utente = entry_utente.get().strip()
    password = entry_password.get()

    if not nome_servizio or not nome_utente or not password:
        messagebox.showwarning("Campi Mancanti", "Servizio, Username/Email e Password sono richiesti.", parent=root)
        return

    data = carica_dati()

    if nome_servizio in data:
        if not messagebox.askyesno("Conferma Sovrascrittura",
                                   f"Esiste già una voce per '{nome_servizio}'.\nVuoi sovrascriverla?",
                                   icon='warning', parent=root):
            return

    data[nome_servizio] = {"utente": nome_utente, "password": password}

    if salva_dati(data):
        messagebox.showinfo("Successo", f"Password per '{nome_servizio}' salvata con successo!", parent=root)
        entry_servizio.delete(0, tk.END)
        entry_utente.delete(0, tk.END)
        entry_password.config(state=tk.NORMAL)
        entry_password.delete(0, tk.END)
        entry_password.config(state='readonly')
        entry_servizio.focus_set()


def mostra_passwords_salvate():
    global root, BUTTON_FONT
    data = carica_dati()

    if not data:
        messagebox.showinfo("Info", "Nessuna password salvata.", parent=root)
        return

    password_window = tk.Toplevel(root)
    password_window.title("Password Salvate")
    password_window.geometry("500x400")
    password_window.configure(bg="#e8e8e8")
    password_window.transient(root)
    password_window.grab_set()

    content_frame = tk.Frame(password_window, bg="#e8e8e8", padx=10, pady=10)
    content_frame.pack(fill=tk.BOTH, expand=True)

    text_frame = tk.Frame(content_frame, bd=1, relief=tk.SUNKEN)
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(0,10))

    text_box = tk.Text(text_frame, width=55, height=15, font=("Courier New", 10), wrap=tk.WORD, borderwidth=0, bg="#ffffff")
    scrollbar = tk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_box.yview)
    text_box.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    sorted_servizi = sorted(data.keys(), key=str.lower)
    for servizio in sorted_servizi:
        info = data.get(servizio, {})
        utente = info.get('utente', 'N/D')
        pwd = info.get('password', 'N/D')
        text_box.insert(tk.END, f"--- {servizio} ---\n", "service_header")
        text_box.insert(tk.END, f"  Username: {utente}\n", "details")
        text_box.insert(tk.END, f"  Password: {pwd}\n\n", "details")

    text_box.tag_configure("service_header", font=("Courier New", 11, "bold"))
    text_box.tag_configure("details", font=("Courier New", 10))

    text_box.config(state=tk.DISABLED)

    close_button = tk.Button(content_frame, text="Chiudi", command=password_window.destroy, width=10, font=BUTTON_FONT, relief=tk.RAISED, borderwidth=2)
    close_button.pack(pady=5)

    center_toplevel(password_window)

    root.wait_window(password_window)


def elimina_password():
    global root
    nome_servizio_da_eliminare = entry_servizio_elimina.get().strip()

    if not nome_servizio_da_eliminare or nome_servizio_da_eliminare == PLACEHOLDER_DELETE:
        messagebox.showwarning("Input Mancante", "Inserisci il nome del servizio/sito da eliminare.", parent=root)
        return

    data = carica_dati()

    if nome_servizio_da_eliminare not in data:
        messagebox.showerror("Errore", f"Il servizio/sito '{nome_servizio_da_eliminare}' non è stato trovato.", parent=root)
        return

    if messagebox.askyesno("Conferma Eliminazione",
                           f"Sei sicuro di voler eliminare la voce per '{nome_servizio_da_eliminare}'?",
                           icon='warning', parent=root):
        del data[nome_servizio_da_eliminare]
        if salva_dati(data):
            messagebox.showinfo("Successo", f"Voce per '{nome_servizio_da_eliminare}' eliminata con successo!", parent=root)
            entry_servizio_elimina.delete(0, tk.END)
            add_placeholder(None)


# --- Helper functions for GUI ---
def show_temp_message(message, duration=2000):
    """Displays a temporary message in the status bar."""
    if 'status_label' in globals() and status_label.winfo_exists():
        status_label.config(text=message)
        if 'root' in globals() and root.winfo_exists():
            root.after(duration, lambda: status_label.config(text=""))

def clear_placeholder(event=None):
    """Clears placeholder text on focus."""
    if entry_servizio_elimina.get() == PLACEHOLDER_DELETE:
        entry_servizio_elimina.delete(0, tk.END)
        entry_servizio_elimina.config(fg='black')

def add_placeholder(event=None):
    """Adds placeholder text if field is empty on focus out."""
    if not entry_servizio_elimina.get().strip():
        entry_servizio_elimina.insert(0, PLACEHOLDER_DELETE)
        entry_servizio_elimina.config(fg='grey')

def center_toplevel(window):
    """Centers a Toplevel window relative to the root."""
    global root
    if 'root' not in globals() or not root.winfo_exists(): return

    window.update_idletasks()
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    win_width = window.winfo_width()
    win_height = window.winfo_height()
    x_pos = root_x + (root_width // 2) - (win_width // 2)
    y_pos = root_y + (root_height // 2) - (win_height // 2)

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    if x_pos < 0: x_pos = 0
    if y_pos < 0: y_pos = 0
    if x_pos + win_width > screen_width: x_pos = screen_width - win_width
    if y_pos + win_height > screen_height: y_pos = screen_height - win_height
    window.geometry(f"+{x_pos}+{y_pos}")



# --- GUI Setup ---
BG_COLOR = "#ffffff"
FG_COLOR_LABEL = "#333333"
FONT_FAMILY = "Segoe UI"
FONT_SIZE_NORMAL = 10
FONT_SIZE_LARGE = 14
FONT_SIZE_TITLE = 18
PLACEHOLDER_DELETE = "Nome servizio/sito da eliminare..."
LOGO_FILENAME = "logo.png"  # <<< NAME OF YOUR LOGO FILE

root = tk.Tk()
root.withdraw()

password_ok = False
while not password_ok:
    master_password = simpledialog.askstring("Password", "Inserisci la tua master password:")
    if not master_password:
        messagebox.showerror("Errore", "Password non fornita.")
    else:
        try:
            carica_dati()
            password_ok = True
        except:
            messagebox.showerror("Errore", "Password errata.")



# --- Main Window ---
root = tk.Tk()

root.title("PassForge") # <<< CHANGED TITLE
root.geometry("550x620")
root.configure(bg=BG_COLOR)

# --- Set Window Icon --- <<< ADDED ICON SETTING
try:
    # This works best for PNG/GIF. Use iconbitmap for ICO on Windows.
    logo_image = tk.PhotoImage(file=LOGO_FILENAME)
    root.iconphoto(True, logo_image) # True applies to future Toplevels too
except tk.TclError as e:
    print(f"Warning: Could not load or set window icon '{LOGO_FILENAME}'. Error: {e}")
    print("Ensure the image file exists in the same directory as the script and is a supported format (PNG, GIF).")
# --- END OF ICON SETTING ---

# --- DEFINE FONTS *AFTER* root exists ---
DEFAULT_FONT = tkFont.Font(family=FONT_FAMILY, size=FONT_SIZE_NORMAL)
LABEL_FONT = tkFont.Font(family=FONT_FAMILY, size=FONT_SIZE_NORMAL)
ENTRY_FONT = tkFont.Font(family=FONT_FAMILY, size=FONT_SIZE_NORMAL)
BUTTON_FONT = tkFont.Font(family=FONT_FAMILY, size=FONT_SIZE_NORMAL, weight="bold")
TITLE_FONT = tkFont.Font(family=FONT_FAMILY, size=FONT_SIZE_TITLE, weight="bold")
STATUS_FONT = tkFont.Font(family=FONT_FAMILY, size=9)

root.option_add("*Font", DEFAULT_FONT)

# --- Main Frame ---
main_frame = tk.Frame(root, bg=BG_COLOR, padx=20, pady=20)
main_frame.pack(fill=tk.BOTH, expand=True)




# --- Title ---
# You can optionally add the logo image to the title area as well
# title_frame = tk.Frame(main_frame, bg=BG_COLOR)
# title_frame.pack(pady=(0, 25))
# if 'logo_image' in locals(): # Check if logo loaded successfully
#    logo_label = tk.Label(title_frame, image=logo_image, bg=BG_COLOR)
#    logo_label.pack(side=tk.LEFT, padx=(0, 10))
# title_label = tk.Label(title_frame, text="PassForge", font=TITLE_FONT, bg=BG_COLOR, fg="#003366")
# title_label.pack(side=tk.LEFT)

# Simpler title without embedded logo:
title_label = tk.Label(main_frame, text="PassForge", font=TITLE_FONT, bg=BG_COLOR, fg="#003366") # <<< CHANGED TITLE HERE TOO
title_label.pack(pady=(0, 25))


# --- Generation Options Frame ---
gen_frame = tk.LabelFrame(main_frame, text=" Opzioni Generazione ", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, padx=15, pady=10, relief=tk.GROOVE, borderwidth=1)
gen_frame.pack(fill=tk.X, pady=(0, 15))
gen_frame.columnconfigure(1, weight=1)

tk.Label(gen_frame, text="Lunghezza:", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
entry_lunghezza = tk.Entry(gen_frame, font=ENTRY_FONT, width=5)
entry_lunghezza.grid(row=0, column=1, pady=5, sticky="w")
entry_lunghezza.insert(0, "16")

cb_frame = tk.Frame(gen_frame, bg=BG_COLOR)
cb_frame.grid(row=1, column=0, columnspan=2, pady=(5, 0), sticky="w")

var_maiuscole = tk.BooleanVar(value=True)
var_minuscole = tk.BooleanVar(value=True)
var_numeri = tk.BooleanVar(value=True)
var_simboli = tk.BooleanVar(value=True)

tk.Checkbutton(cb_frame, text="Maiuscole (A-Z)", variable=var_maiuscole, font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=(0, 10))
tk.Checkbutton(cb_frame, text="Minuscole (a-z)", variable=var_minuscole, font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=(0, 10))
tk.Checkbutton(cb_frame, text="Numeri (0-9)", variable=var_numeri, font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=(0, 10))
tk.Checkbutton(cb_frame, text="Simboli (!@#..)", variable=var_simboli, font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, activebackground=BG_COLOR).pack(side=tk.LEFT)

# --- Account Details Frame ---
details_frame = tk.LabelFrame(main_frame, text=" Dati Account ", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, padx=15, pady=10, relief=tk.GROOVE, borderwidth=1)
details_frame.pack(fill=tk.X, pady=(0, 15))
details_frame.columnconfigure(1, weight=1)

tk.Label(details_frame, text="Servizio/Sito:", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
entry_servizio = tk.Entry(details_frame, font=ENTRY_FONT, width=40)
entry_servizio.grid(row=0, column=1, pady=5, sticky="ew")

tk.Label(details_frame, text="Username/Email:", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL).grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
entry_utente = tk.Entry(details_frame, font=ENTRY_FONT, width=40)
entry_utente.grid(row=1, column=1, pady=5, sticky="ew")

tk.Label(details_frame, text="Password:", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL).grid(row=2, column=0, padx=(0, 10), pady=5, sticky="w")
entry_password = tk.Entry(details_frame, font=ENTRY_FONT, width=40, state='normal', readonlybackground="#ffffff")
entry_password.grid(row=2, column=1, pady=5, sticky="ew")

# --- Action Buttons Frame ---
action_frame = tk.Frame(main_frame, bg=BG_COLOR)
action_frame.pack(pady=(10, 20))

button_style = {'font': BUTTON_FONT, 'padx': 12, 'pady': 5, 'relief': tk.RAISED, 'borderwidth': 2}

button_generare = tk.Button(action_frame, text="Genera Password", bg="#4CAF50", fg='white', command=on_generare_password, **button_style)
button_generare.pack(side=tk.LEFT, padx=8)

button_salvare = tk.Button(action_frame, text="Salva Password", bg="#2196F3", fg='white', command=on_salvare_password, **button_style)
button_salvare.pack(side=tk.LEFT, padx=8)

button_mostra = tk.Button(action_frame, text="Mostra Salvate", bg="#FF9800", fg='black', command=mostra_passwords_salvate, **button_style)
button_mostra.pack(side=tk.LEFT, padx=8)


# --- Delete Section Frame ---
delete_frame = tk.LabelFrame(main_frame, text=" Elimina Voce ", font=LABEL_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, padx=15, pady=10, relief=tk.GROOVE, borderwidth=1)
delete_frame.pack(fill=tk.X, pady=(0, 15))
delete_frame.columnconfigure(0, weight=1)

entry_servizio_elimina = tk.Entry(delete_frame, font=ENTRY_FONT, width=35, fg='grey')
entry_servizio_elimina.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="ew")
entry_servizio_elimina.insert(0, PLACEHOLDER_DELETE)
entry_servizio_elimina.bind("<FocusIn>", clear_placeholder)
entry_servizio_elimina.bind("<FocusOut>", add_placeholder)

button_eliminare = tk.Button(delete_frame, text="Elimina", bg="#F44336", command=elimina_password, font=BUTTON_FONT, fg="white", padx=10, pady=2, relief=tk.RAISED, borderwidth=2)
button_eliminare.grid(row=0, column=1, pady=5)

# --- Status Bar ---
status_label = tk.Label(main_frame, text="", font=STATUS_FONT, bg=BG_COLOR, fg=FG_COLOR_LABEL, anchor="w")
status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))


# --- Set initial focus ---
entry_servizio.focus_set()

# --- Start Main Loop ---
root.mainloop()