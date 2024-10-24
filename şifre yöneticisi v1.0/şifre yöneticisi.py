import customtkinter as ctk
from cryptography.fernet import Fernet
import json
import os
import pyperclip
import tkinter as tk
from tkinter import messagebox, filedialog
import random
import string
import hashlib
import threading
import time
import csv
from datetime import datetime

# Ayarlar
ctk.set_appearance_mode("System")  # 'System', 'Dark', 'Light'
ctk.set_default_color_theme("blue")  # 'blue', 'green', 'dark-blue'

# Dosya Adları
KEY_FILE = 'key.key'
DATA_FILE = 'data.json'
PASSWORD_HASH_FILE = 'password.hash'
LOCKOUT_FILE = 'lockout.json'  # Hesap kilitleme durumu için dosya

def generate_key():
    """Yeni bir şifreleme anahtarı oluşturur ve kaydeder."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Mevcut şifreleme anahtarını yükler veya yoksa oluşturur."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

def hash_password(password, salt=None):
    """Şifreyi hash'ler. Eğer salt verilmezse yeni bir salt oluşturur."""
    if not salt:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + pwd_hash

def verify_password(stored_password_hash, provided_password):
    """Verilen şifreyi hash'leyip doğrular."""
    salt = stored_password_hash[:16]
    stored_hash = stored_password_hash[16:]
    pwd_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return pwd_hash == stored_hash

def load_data(cipher_suite):
    """Veri dosyasını yükler. Dosya yoksa boş bir dict döner."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        try:
            encrypted_data = file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            data = json.loads(decrypted_data)
        except (json.JSONDecodeError, Exception):
            data = {}
    return data

def save_data(data, cipher_suite):
    """Veriyi JSON dosyasına şifrelenmiş olarak kaydeder."""
    data_json = json.dumps(data).encode()
    encrypted_data = cipher_suite.encrypt(data_json)
    with open(DATA_FILE, 'wb') as file:
        file.write(encrypted_data)

def load_lockout_info():
    """Hesap kilitleme bilgilerini yükler veya yoksa boş bir dict döner."""
    if not os.path.exists(LOCKOUT_FILE):
        return {}
    with open(LOCKOUT_FILE, 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = {}
    return data

def save_lockout_info(lockout_info):
    """Hesap kilitleme bilgilerini kaydeder."""
    with open(LOCKOUT_FILE, 'w') as file:
        json.dump(lockout_info, file, indent=4)

class PasswordManager(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Şifre Yöneticisi-KeplerB")
        self.geometry("500x400")  # Giriş ekranı için daha uygun boyut
        self.iconbitmap("logo.ico")
        self.resizable(False, False)
        self.configure(padx=20, pady=20)

        self.key = load_key()
        self.cipher_suite = Fernet(self.key)
        self.data = load_data(self.cipher_suite)
        self.show_password = False  # Şifre görünürlüğü kontrolü

        # Hesap Kilitleme Ayarları
        self.lockout_info = load_lockout_info()
        self.max_attempts = 3
        self.base_wait_time = 30  # İlk kilitlenme süresi (saniye)
        self.wait_increment = 30  # Kilitlenme süresi artışı (saniye)

        if not os.path.exists(PASSWORD_HASH_FILE):
            self.first_time_setup()
        else:
            self.load_master_password()

    def first_time_setup(self):
        """İlk kurulumda master şifre ayarlar."""
        self.clear_widgets()
        self.setup_master_password_setup()

    def setup_master_password_setup(self):
        """Master şifre ayar ekranını oluşturur."""
        self.title("Master Şifre Ayarlama")
        self.geometry("400x300")

        info_label = ctk.CTkLabel(self, text="Yeni bir master şifre belirleyin.", font=ctk.CTkFont(size=16, weight="bold"))
        info_label.pack(pady=(20, 10))

        # Master Şifre Giriş
        self.master_password_entry = ctk.CTkEntry(self, show="*", placeholder_text="Master Şifre", width=250)
        self.master_password_entry.pack(pady=10)

        # Master Şifre Onay
        self.master_password_confirm_entry = ctk.CTkEntry(self, show="*", placeholder_text="Şifreyi Onaylayın", width=250)
        self.master_password_confirm_entry.pack(pady=10)

        # Kaydet ve Hakkında Butonları
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=20)

        save_button = ctk.CTkButton(button_frame, text="Kaydet", command=self.save_master_password,font=ctk.CTkFont(weight="bold"))
        save_button.pack(side="left", padx=(0, 10))

        about_button = ctk.CTkButton(button_frame, text="Hakkında", command=self.show_about_info,font=ctk.CTkFont(weight="bold"))
        about_button.pack(side="left")

    def show_about_info(self):
        """Hakkında penceresini açar."""
        about_window = ctk.CTkToplevel(self)
        about_window.title("Hakkında")
        about_window.geometry("500x465")
        about_window.resizable(False, False)

        # Başlık
        title_label = ctk.CTkLabel(
            about_window,
            text="Şifre Yöneticisi Uygulaması",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        title_label.pack(pady=(20, 10))

        # Açıklama
        description_label = ctk.CTkLabel(
            about_window,
            text=("Bu uygulama, kullanıcıların şifrelerini güvenli bir şekilde yönetmesine yardımcı olmak amacıyla "
                  "tasarlanmıştır. Şifrelerinizi şifreleyip güvenli bir şekilde saklar, gerektiğinde şifreleri "
                  "görüntüleme, kopyalama ve düzenleme imkanı sağlar.\n\n"
                  "Özellikler:\n"
                  "- Şifrelerinizi güvende tutma\n"
                  "- Rastgele şifre oluşturabilme\n"
                  "- Rastgele kullanıcı adı oluşturabilme\n"
                  "- Şifreleri dışa ve içe aktarabilme\n"
                  "- Şifre gücü değerlendirme\n"
                  "- Şifre Sıfırlama\n"
                  "- Kullanıcı Dostu Arayüz\n\n"
                  "Version: 1.0.0"),
            font=ctk.CTkFont(size=14),
            wraplength=400,
            justify="left"
        )
        description_label.pack(pady=(10, 20), padx=20)

        # Geliştirici Bilgisi
        developer_label = ctk.CTkLabel(
            about_window,
            text="Geliştirici: KeplerB",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        developer_label.pack(pady=(10, 0))

        # Alt Bilgi
        footer_label = ctk.CTkLabel(
            about_window,
            text="®2024 Şifre Yöneticisi. Tüm Hakları Saklıdır.",
            font=ctk.CTkFont(size=12),
            anchor="w"
        )
        footer_label.pack(side="bottom", padx=20, pady=(0, 10), anchor="sw")

        # Kapat Butonu
        close_button = ctk.CTkButton(about_window,text="Kapat", font=ctk.CTkFont(weight="bold"), command=about_window.destroy)
        close_button.pack(pady=10)

    def load_master_password(self):
        """Master şifre doğrulama ekranını yükler."""
        self.clear_widgets()
        self.title("Şifre Yöneticisi-KeplerB")
        self.geometry("300x200")

        # Başlık
        self.info_label = ctk.CTkLabel(self, text="Giriş Yap", font=ctk.CTkFont(size=16, weight="bold"))
        self.info_label.pack(pady=(20, 10))

        self.stored_password_hash = b""
        if os.path.exists(PASSWORD_HASH_FILE):
            with open(PASSWORD_HASH_FILE, 'rb') as file:
                self.stored_password_hash = file.read()

        # Master Şifre Giriş Alanı
        self.password_entry_login = ctk.CTkEntry(
            self,
            show="*",
            placeholder_text="Master Şifre",
            width=250
        )
        self.password_entry_login.pack(pady=(20, 10))

        # Butonları içeren çerçeve
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=(10, 10))

        # Giriş Yap Butonu
        self.login_button = ctk.CTkButton(button_frame, text="Giriş Yap", command=self.verify_password, width=15)
        self.login_button.pack(side="left", padx=(0, 10))

        # Şifreyi Unuttum Butonu
        self.forgot_password_button = ctk.CTkButton(button_frame, text="Şifremi Unuttum", command=self.forgot_password, fg_color="red", width=15)
        self.forgot_password_button.pack(side="left", padx=(10, 0))

        # Enter tuşuyla giriş yapma
        self.bind("<Return>", lambda event: self.verify_password())

    def verify_password(self):
        """Master şifresini doğrular.""" 
        entered_password = self.password_entry_login.get()

        # Hesap Kilitleme Kontrolü
        lockout_entry = self.lockout_info.get('lockout_until', 0)
        current_time = time.time()
        if current_time < lockout_entry:
            remaining = int(lockout_entry - current_time)
            messagebox.showwarning("Kilitleme", f"Çok fazla yanlış giriş denemesi. Lütfen {remaining} saniye bekleyin.")
            return

        if verify_password(self.stored_password_hash, entered_password):
            # Doğru şifre girildiğinde kilitleme bilgilerini sıfırla
            self.lockout_info['attempts'] = 0
            self.lockout_info['lockout_until'] = 0
            save_lockout_info(self.lockout_info)

            # Giriş ekranı widget'larını kaldır
            self.clear_widgets()  # Bütün giriş ekranını kaldırır
            self.start_application()
        else:
            # Yanlış şifre girildiğinde deneme sayısını artır
            self.lockout_info['attempts'] = self.lockout_info.get('attempts', 0) + 1
            attempts = self.lockout_info['attempts']

            if attempts >= self.max_attempts:
                # Kilitleme süresini hesapla
                lockout_time = self.base_wait_time + (self.lockout_info.get('lockout_count', 0) * self.wait_increment)
                self.lockout_info['lockout_until'] = time.time() + lockout_time
                self.lockout_info['lockout_count'] = self.lockout_info.get('lockout_count', 0) + 1
                self.lockout_info['attempts'] = 0  # Denemeleri sıfırla
                save_lockout_info(self.lockout_info)
                messagebox.showerror("Hata", f"Çok fazla yanlış giriş denemesi. Lütfen {lockout_time} saniye bekleyin.")
            else:
                remaining = self.max_attempts - attempts
                messagebox.showerror("Hata", f"Yanlış master şifre. {remaining} deneme kaldı.")
                save_lockout_info(self.lockout_info)

    def forgot_password(self):
        """Kullanıcı şifreyi unuttuğunda sıfırlama seçeneklerini sunar."""
        response = messagebox.askyesno("Şifre Sıfırlama", "Master şifrenizi sıfırlamak istiyor musunuz? Bu işlem sadece şifrenizi sıfırlayacak ve mevcut verilerinizi koruyacaktır.")
        if response:
            # Mevcut şifreyi sıfırla
            if os.path.exists(PASSWORD_HASH_FILE):
                os.remove(PASSWORD_HASH_FILE)

            messagebox.showinfo("Başarılı", "Master şifreniz sıfırlandı. Yeni bir master şifre belirleyin.")
            self.first_time_setup()

    def save_master_password(self):
        """Master şifreyi hash'leyip kaydeder."""
        pwd1 = self.master_password_entry.get()
        pwd2 = self.master_password_confirm_entry.get()

        if not pwd1 or not pwd2:
            messagebox.showwarning("Uyarı", "Lütfen her iki şifre alanını da doldurun.")
            return

        if pwd1 != pwd2:
            messagebox.showerror("Hata", "Şifreler uyuşmuyor.")
            return

        hashed_pwd = hash_password(pwd1)
        with open(PASSWORD_HASH_FILE, 'wb') as file:
            file.write(hashed_pwd)

        messagebox.showinfo("Başarılı", "Master şifreniz başarıyla ayarlandı.")
        self.load_master_password()

    def start_application(self):
        """Ana uygulamanın bileşenlerini oluşturur."""
        self.title("Şifre Yöneticisi-KeplerB")
        self.geometry("800x900")
        self.resizable(True, True)
        self.configure(padx=20, pady=20)
        self.create_widgets()

    def create_widgets(self):
        """Ana uygulama bileşenlerini oluşturur."""
        # Üst Çubuk (Arama)
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(fill="x", pady=(0, 10))

        search_label = ctk.CTkLabel(top_frame, text="Ara:")
        search_label.pack(side="left", padx=(0, 10))

        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.populate_checklist())
        search_entry = ctk.CTkEntry(top_frame, textvariable=self.search_var, placeholder_text="Web sitesi, kullanıcı adı veya email")
        search_entry.pack(side="left", fill="x", expand=True)

        # Şifre Ekleme Bölümü
        add_frame = ctk.CTkFrame(self, corner_radius=10)
        add_frame.pack(pady=10, fill="x")

        # Web Sitesi
        website_label = ctk.CTkLabel(add_frame, text="Web Sitesi:", anchor="w", font=ctk.CTkFont(weight="bold"))
        website_label.grid(row=0, column=0, pady=10, padx=10, sticky="w")
        self.website_entry = ctk.CTkEntry(add_frame, placeholder_text="Örneğin: example.com")
        self.website_entry.grid(row=0, column=1, pady=10, padx=10, sticky="ew")

        # Email
        email_label = ctk.CTkLabel(add_frame, text="Email:", anchor="w", font=ctk.CTkFont(weight="bold"))
        email_label.grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.email_entry = ctk.CTkEntry(add_frame, placeholder_text="Örneğin: user@example.com")
        self.email_entry.grid(row=1, column=1, pady=10, padx=10, sticky="ew")

        # Kullanıcı Adı
        username_label = ctk.CTkLabel(add_frame, text="Kullanıcı Adı:", anchor="w", font=ctk.CTkFont(weight="bold"))
        username_label.grid(row=2, column=0, pady=10, padx=10, sticky="w")
        self.username_entry = ctk.CTkEntry(add_frame, placeholder_text="Örneğin: user123")
        self.username_entry.grid(row=2, column=1, pady=10, padx=10, sticky="ew")

        # Rastgele Kullanıcı Adı Oluşturma Butonu
        generate_username_button = ctk.CTkButton(add_frame, text="Rastgele Kullanıcı Adı", command=self.generate_random_username)
        generate_username_button.grid(row=2, column=2, pady=10, padx=10)

        # Şifre
        password_label = ctk.CTkLabel(add_frame, text="Şifre:", anchor="w", font=ctk.CTkFont(weight="bold"))
        password_label.grid(row=3, column=0, pady=10, padx=10, sticky="w")
        self.password_entry_add = ctk.CTkEntry(add_frame, show="*", placeholder_text="Şifrenizi girin")
        self.password_entry_add.grid(row=3, column=1, pady=10, padx=10, sticky="ew")
        self.password_entry_add.bind("<KeyRelease>", self.on_password_entry_change)

        # Şifre Güç Göstergesi (Alt Kısımda)
        self.password_strength_var = tk.DoubleVar()
        self.password_strength_bar = ctk.CTkProgressBar(add_frame, variable=self.password_strength_var, width=200)
        self.password_strength_bar.grid(row=4, column=1, pady=(0, 10), padx=10, sticky="w")
        self.password_strength_label = ctk.CTkLabel(add_frame, text="Güç: Zayıf", anchor="w")
        self.password_strength_label.grid(row=5, column=1, pady=(0, 10), padx=10, sticky="w")

        # Rastgele Şifre Oluşturma Butonu
        generate_password_button = ctk.CTkButton(add_frame, text="Rastgele Şifre Oluştur", command=self.generate_random_password)
        generate_password_button.grid(row=3, column=2, pady=10, padx=10)

        # Şifre Göster/Gizle Butonu
        self.toggle_button = ctk.CTkButton(add_frame, text="Göster", width=60, command=self.toggle_password_visibility)
        self.toggle_button.grid(row=3, column=3, pady=10, padx=10)

        # Şifre Ekleme Butonu
        add_button = ctk.CTkButton(add_frame, text="Şifre Ekle", command=self.add_password, fg_color="green")
        add_button.grid(row=6, column=0, columnspan=4, pady=20, padx=10, sticky="ew")

        # Şifre Listeleme Bölümü
        self.checklist_frame = ctk.CTkScrollableFrame(self, corner_radius=10, height=300)
        self.checklist_frame.pack(pady=20, fill="both", expand=True)

        self.populate_checklist()  # Checkbox listesini doldur

        # Şifre Silme ve Güncelleme Butonları
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(pady=10)

        delete_button = ctk.CTkButton(
            button_frame,
            text="Seçili Şifreleri Sil",
            fg_color="red",
            hover_color="#FF5C5C",
            command=self.confirm_delete_passwords
        )
        delete_button.grid(row=0, column=0, padx=5)

        update_button = ctk.CTkButton(
            button_frame,
            text="Seçili Şifreleri Güncelle",
            command=self.open_update_window
        )
        update_button.grid(row=0, column=1, padx=5)

        # İçe Aktarma ve Dışa Aktarma Butonları
        export_button = ctk.CTkButton(button_frame, text="Şifreleri Dışa Aktar", command=self.export_passwords)
        export_button.grid(row=0, column=2, padx=5)

        import_button = ctk.CTkButton(button_frame, text="Şifreleri İçe Aktar", command=self.import_passwords)
        import_button.grid(row=0, column=3, padx=5)

        # Grid'de Sütun Ağırlıklarını Ayarlama
        add_frame.grid_columnconfigure(1, weight=1)  # Web Sitesi, Email, Kullanıcı Adı ve Şifre giriş alanlarının genişlemesini sağlar

    def clear_widgets(self):
        """Tüm mevcut widget'ları temizler."""
        for widget in self.winfo_children():
            widget.destroy()

    def toggle_password_visibility(self):
        """Şifre girişinin görünürlüğünü değiştirir.""" 
        self.show_password = not self.show_password
        if self.show_password:
            self.password_entry_add.configure(show="")
            self.toggle_button.configure(text="Gizle")
        else:
            self.password_entry_add.configure(show="*")
            self.toggle_button.configure(text="Göster")

    def add_password(self):
        """Yeni bir şifre ekler.""" 
        website = self.website_entry.get().strip()
        email = self.email_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry_add.get().strip()

        if not website or not username or not email or not password:
            messagebox.showwarning("Uyarı", "Lütfen tüm alanları doldurun.")
            return

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        creation_date = datetime.now().strftime("%d-%m-%Y")  # Gün/Ay/Yıl formatında
        self.data[website] = {
            "username": username,
            "email": email,
            "password": encrypted_password,
            "creation_date": creation_date  # Oluşturma tarihi burada
        }
        save_data(self.data, self.cipher_suite)
        self.populate_checklist()  # Listeyi güncelle
        messagebox.showinfo("Başarılı", f"{website} için şifre eklendi.")
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry_add.delete(0, tk.END)
        self.password_strength_var.set(0)
        self.password_strength_label.configure(text="Güç: Zayıf")

    def populate_checklist(self):
        """Checkbox listesini doldurur.""" 
        for widget in self.checklist_frame.winfo_children():
            widget.destroy()

        search_query = self.search_var.get().lower()

        self.check_vars = {}
        for website, creds in self.data.items():
            if search_query and search_query not in website.lower() and search_query not in creds["username"].lower() and search_query not in creds["email"].lower():
                continue

            frame = ctk.CTkFrame(self.checklist_frame)
            frame.pack(fill="x", padx=10, pady=5)

            var = tk.BooleanVar()
            self.check_vars[website] = var

            checkbox = ctk.CTkCheckBox(frame, variable=var, text=website)
            checkbox.pack(side="left", fill="x", expand=True)

            details_button = ctk.CTkButton(frame, text="Detaylar", command=lambda w=website: self.show_details(w))
            details_button.pack(side="right", padx=(0, 5))

    def show_details(self, website):
        """Seçilen web sitesinin detaylarını gösterir.""" 
        creds = self.data.get(website)
        if not creds:
            messagebox.showerror("Hata", "Seçilen web sitesi bulunamadı.")
            return

        username = creds["username"]
        email = creds["email"]
        encrypted_password = creds["password"]
        creation_date = creds["creation_date"]

        try:
            password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except Exception:
            messagebox.showerror("Hata", "Şifre çözülemedi.")
            return

        # Pencereyi ayarla
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"{website} Detayları")
        details_window.geometry("500x450")  # Pencere boyutu genişletildi ve düzenlendi
        details_window.resizable(False, False)

        # Başlık
        title_label = ctk.CTkLabel(details_window, text=f"{website} Detayları", font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=(20, 30))

        # Kullanıcı Adı Kutucuğu
        username_frame = ctk.CTkFrame(details_window)
        username_frame.pack(pady=10, padx=20, fill="x")
        username_label = ctk.CTkLabel(username_frame, text="Kullanıcı Adı:", font=ctk.CTkFont(size=16, weight="bold"))
        username_label.pack(side="left", padx=10)
        username_value = ctk.CTkLabel(username_frame, text=username, font=ctk.CTkFont(size=14))
        username_value.pack(side="left", padx=10)

        # Email Kutucuğu
        email_frame = ctk.CTkFrame(details_window)
        email_frame.pack(pady=10, padx=20, fill="x")
        email_label = ctk.CTkLabel(email_frame, text="Email:", font=ctk.CTkFont(size=16, weight="bold"))
        email_label.pack(side="left", padx=10)
        email_value = ctk.CTkLabel(email_frame, text=email, font=ctk.CTkFont(size=14))
        email_value.pack(side="left", padx=10)

        # Şifre Kutucuğu
        password_frame = ctk.CTkFrame(details_window)
        password_frame.pack(pady=10, padx=20, fill="x")
        password_label = ctk.CTkLabel(password_frame, text="Şifre:", font=ctk.CTkFont(size=16, weight="bold"))
        password_label.pack(side="left", padx=10)
        password_value = ctk.CTkLabel(password_frame, text=password, font=ctk.CTkFont(size=14))
        password_value.pack(side="left", padx=10)

        # Oluşturulma Tarihi Kutucuğu
        creation_date_frame = ctk.CTkFrame(details_window)
        creation_date_frame.pack(pady=10, padx=20, fill="x")
        creation_date_label = ctk.CTkLabel(creation_date_frame, text="Oluşturulma Tarihi:", font=ctk.CTkFont(size=16, weight="bold"))
        creation_date_label.pack(side="left", padx=10)
        creation_date_value = ctk.CTkLabel(creation_date_frame, text=creation_date, font=ctk.CTkFont(size=14))
        creation_date_value.pack(side="left", padx=10)

        # Bilgileri Kopyala ve Kapat Butonları
        button_frame = ctk.CTkFrame(details_window)
        button_frame.pack(pady=30)

        copy_button = ctk.CTkButton(button_frame, text="Bilgileri Kopyala", command=lambda: self.copy_to_clipboard(f"{website}\nKullanıcı Adı: {username}\nEmail: {email}\nŞifre: {password}\nOluşturulma Tarihi: {creation_date}"))
        copy_button.pack(side="left", padx=10)

        close_button = ctk.CTkButton(button_frame, text="Kapat", command=details_window.destroy)
        close_button.pack(side="left")

    def confirm_delete_passwords(self):
        """Seçilen şifreleri silme onayı alır.""" 
        selected = [website for website, var in self.check_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("Uyarı", "Silinecek şifre seçilmedi.")
            return

        if messagebox.askyesno("Onay", "Seçili şifreleri silmek istediğinize emin misiniz?"):
            self.delete_selected_passwords()

    def delete_selected_passwords(self):
        """Seçili şifreleri siler.""" 
        to_delete = [website for website, var in self.check_vars.items() if var.get()]
        for website in to_delete:
            del self.data[website]
        save_data(self.data, self.cipher_suite)
        self.populate_checklist()  # Listeyi güncelle
        messagebox.showinfo("Başarılı", "Seçilen şifreler silindi.")

    def open_update_window(self):
        """Seçilen şifreleri güncellemek için bir pencere açar.""" 
        if len(self.data) == 0:
            messagebox.showinfo("Bilgi", "Kayıtlı şifre bulunamadı.")
            return

        selected_websites = [website for website, var in self.check_vars.items() if var.get()]

        if len(selected_websites) == 0:
            messagebox.showwarning("Uyarı", "Güncellemek için bir hesap seçin.")
            return

        if len(selected_websites) > 1:
            messagebox.showwarning("Uyarı", "Bir seferde yalnızca bir hesap güncellenebilir.")
            return

        website = selected_websites[0]
        creds = self.data.get(website)
        if not creds:
            messagebox.showerror("Hata", "Seçilen web sitesi bulunamadı.")
            return

        current_username = creds["username"]
        current_email = creds["email"]
        current_encrypted_password = creds["password"]
        current_creation_date = creds["creation_date"]

        try:
            current_password = self.cipher_suite.decrypt(current_encrypted_password.encode()).decode()
        except Exception:
            messagebox.showerror("Hata", "Şifre çözülemedi.")
            return

        update_window = ctk.CTkToplevel(self)
        update_window.title(f"{website} Güncelle")
        update_window.geometry("400x500")  # Pencere boyutu güncellendi
        update_window.resizable(False, False)

        # Web Sitesi Giriş Alanı
        website_label = ctk.CTkLabel(update_window, text="Web Sitesi:", font=ctk.CTkFont(weight="bold"))
        website_label.pack(pady=(20, 5), anchor="w", padx=20)
        website_entry = ctk.CTkEntry(update_window, width=300)
        website_entry.insert(0, website)
        website_entry.pack(pady=5, padx=20)

        # Email Giriş Alanı
        email_label = ctk.CTkLabel(update_window, text="Email:", font=ctk.CTkFont(weight="bold"))
        email_label.pack(pady=(10, 5), anchor="w", padx=20)
        email_entry = ctk.CTkEntry(update_window, width=300)
        email_entry.insert(0, current_email)
        email_entry.pack(pady=5, padx=20)

        # Kullanıcı Adı Giriş Alanı
        username_label = ctk.CTkLabel(update_window, text="Kullanıcı Adı:", font=ctk.CTkFont(weight="bold"))
        username_label.pack(pady=(10, 5), anchor="w", padx=20)
        username_entry = ctk.CTkEntry(update_window, width=300)
        username_entry.insert(0, current_username)
        username_entry.pack(pady=5, padx=20)

        # Şifre Giriş Alanı ve Göster/Gizle Butonu
        password_label = ctk.CTkLabel(update_window, text="Şifre:", font=ctk.CTkFont(weight="bold"))
        password_label.pack(pady=(10, 5), anchor="w", padx=20)

        password_frame = ctk.CTkFrame(update_window)
        password_frame.pack(pady=5, padx=20, fill="x")

        password_entry = ctk.CTkEntry(password_frame, show="*", width=250)
        password_entry.insert(0, current_password)
        password_entry.pack(side="left", expand=True, fill="x")
        toggle_update_password = ctk.CTkButton(
            password_frame,
            text="Göster",
            width=60,
            command=lambda: self.toggle_update_password_visibility(password_entry, toggle_update_password)
        )
        toggle_update_password.pack(side="left", padx=(10, 0))

        # Şifre Güç Göstergesi (Alt Kısımda)
        self.update_password_strength_var = tk.DoubleVar()
        self.update_password_strength_bar = ctk.CTkProgressBar(update_window, variable=self.update_password_strength_var, width=200)
        self.update_password_strength_bar.pack(pady=(10, 0), padx=20, anchor="w")
        self.update_password_strength_label = ctk.CTkLabel(update_window, text="Güç: Zayıf", anchor="w")
        self.update_password_strength_label.pack(pady=(0, 10), padx=20, anchor="w")

        # Güncelle Butonu
        update_button = ctk.CTkButton(
            update_window,
            text="Güncelle",
            command=lambda: self.update_password(
                old_website=website,
                new_website=website_entry.get().strip(),
                email=email_entry.get().strip(),
                username=username_entry.get().strip(),
                password=password_entry.get().strip(),
                update_window=update_window
            )
        )
        update_button.pack(pady=20, padx=20, fill="x")

    def toggle_update_password_visibility(self, password_entry, toggle_button):
        """Güncelleme penceresindeki şifre görünürlüğünü değiştirir."""
        if password_entry.cget('show') == '':
            password_entry.configure(show="*")
            toggle_button.configure(text="Göster")
        else:
            password_entry.configure(show="")
            toggle_button.configure(text="Gizle")

    def update_password(self, old_website, new_website, email, username, password, update_window):
        """Şifreyi ve/veya web sitesini günceller.""" 
        if not new_website or not username or not email or not password:
            messagebox.showwarning("Uyarı", "Lütfen tüm alanları doldurun.")
            return

        if new_website != old_website and new_website in self.data:
            messagebox.showerror("Hata", "Yeni web sitesi adı zaten mevcut.")
            return

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        # Eğer web sitesi adı değişmişse, eski anahtarı silip yenisini ekle
        if new_website != old_website:
            del self.data[old_website]

        creation_date = datetime.now().strftime("%d-%m-%Y")  # Gün/Ay/Yıl formatında
        self.data[new_website] = {"username": username, "email": email, "password": encrypted_password, "creation_date": creation_date}
        save_data(self.data, self.cipher_suite)
        self.populate_checklist()  # Listeyi güncelle
        messagebox.showinfo("Başarılı", f"{new_website} için şifre güncellendi.")
        update_window.destroy()

    def generate_random_username(self):
        """Rastgele bir kullanıcı adı oluşturur.""" 
        random_username = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        self.username_entry.delete(0, tk.END)  # Kullanıcı adı girişini temizle
        self.username_entry.insert(0, random_username)  # Rastgele kullanıcı adını ekle

    def generate_random_password(self):
        """Rastgele bir şifre oluşturur.""" 
        length = 12  # Şifrenin uzunluğu
        characters = string.ascii_letters + string.digits + string.punctuation  # Kullanılacak karakterler
        random_password = ''.join(random.choices(characters, k=length))
        self.password_entry_add.delete(0, tk.END)  # Şifre girişini temizle
        self.password_entry_add.insert(0, random_password)  # Rastgele şifreyi ekle
        self.evaluate_password_strength(random_password, self.password_strength_var, self.password_strength_label)

    def on_password_entry_change(self, event):
        """Şifre ekleme alanındaki şifre gücünü değerlendirir.""" 
        password = self.password_entry_add.get()
        self.evaluate_password_strength(password, self.password_strength_var, self.password_strength_label)

    def evaluate_password_strength(self, password, strength_var, strength_label):
        """Şifrenin gücünü değerlendirir ve göstergeleri günceller.""" 
        strength = 0
        criteria = [
            len(password) >= 8,
            any(c.islower() for c in password) and any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password)
        ]
        strength = sum(criteria)

        # Güç seviyesini ayarla
        if strength <= 1:
            strength_label.configure(text="Güç: Zayıf", text_color="red")
            strength_var.set(0.25)
        elif strength == 2:
            strength_label.configure(text="Güç: Orta", text_color="orange")
            strength_var.set(0.5)
        elif strength == 3:
            strength_label.configure(text="Güç: İyi", text_color="yellow")
            strength_var.set(0.75)
        elif strength == 4:
            strength_label.configure(text="Güç: Çok Güçlü", text_color="green")
            strength_var.set(1.0)

    def export_passwords(self):
        """Seçili şifreleri CSV dosyasına aktarır."""
        selected = [website for website, var in self.check_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("Uyarı", "Dışa aktarılacak şifre seçilmedi.")
            return

        export_file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not export_file_path:
            return  # Kullanıcı dosya seçmezse çık

        with open(export_file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Website", "Username", "Email", "Password", "Creation Date"])  # Header
            for website in selected:
                creds = self.data[website]
                decrypted_password = self.cipher_suite.decrypt(creds["password"].encode()).decode()
                writer.writerow([website, creds["username"], creds["email"], decrypted_password, creds["creation_date"]])
        messagebox.showinfo("Başarılı", f"Seçili şifreler {export_file_path} dosyasına aktarıldı.")

    def import_passwords(self):
        """CSV dosyasından şifreleri içe aktarır."""
        import_file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])  # Kullanıcıdan dosya yolu al
        if not import_file_path:
            return  # Kullanıcı dosya seçmezse çık
        try:
            with open(import_file_path, mode='r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    website = row["Website"]
                    username = row["Username"]
                    email = row["Email"]
                    password = row["Password"]
                    creation_date = row["Creation Date"]

                    # Encrypt the password before storing
                    encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

                    # Add to the data dictionary
                    self.data[website] = {
                        "username": username,
                        "email": email,
                        "password": encrypted_password,
                        "creation_date": creation_date  # Use the imported creation date
                    }
                save_data(self.data, self.cipher_suite)
                self.populate_checklist()  # Update the checklist
                messagebox.showinfo("Başarılı", "Şifreler başarıyla içe aktarıldı.")
        except Exception as e:
            messagebox.showerror("Hata", f"İçe aktarma sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()
