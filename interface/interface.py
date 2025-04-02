# --- Importation ---
import csv
import os
import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets
import string
import pandas as pd
import requests

# --- Initialisation ---
USERS_FILE = "users_admin.csv"
API_URL = "https://guardia-api.iadjedj.ovh/update_badge"  
TOKEN_URL = "https://guardia-api.iadjedj.ovh/token?exp=120"
CREER_API = "https://guardia-api.iadjedj.ovh/create_badge"
DELETE_BADGE = "https://guardia-api.iadjedj.ovh/delete_badge"
username = "admin_123"
password = "password_456"

#INTERFACE GRAPHIQUE

# --- Fonctions de connexion ---
def generer_mdp(longueur=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(longueur))

def generer_sel(longueur=16):
    return secrets.token_hex(longueur)

def hacher_mot_de_passe(mot_de_passe, sel):
    return hashlib.sha256((mot_de_passe + sel).encode('utf-8')).hexdigest()

def lire_utilisateurs():
    if os.path.exists(USERS_FILE):
        df = pd.read_csv(USERS_FILE, encoding="utf-8-sig")
        print("Utilisateurs lus depuis le fichier :")
        print(df)  # 🔹 Affiche ce qui est lu depuis le fichier
        return df
    else:
        return pd.DataFrame(columns=["username", "password_hash", "salt", "Nom", "Prénom", "Adresse", "Email", "Téléphone"])

def enregistrer_utilisateur(username, password, nom, prenom, adresse, email, telephone):
    utilisateurs = lire_utilisateurs()
    if username in utilisateurs["username"].values:
        messagebox.showerror("Erreur", "L'utilisateur existe déjà.")
        return False

    sel = generer_sel()
    mot_de_passe_hache = hacher_mot_de_passe(password, sel)

    # Ajouter les informations supplémentaires lors de la création de l'utilisateur
    nouvel_utilisateur = pd.DataFrame([{"username": username, "password_hash": mot_de_passe_hache, "salt": sel, "Nom": nom, "Prénom": prenom, "Adresse": adresse, "Email": email, "Téléphone": telephone}])
    utilisateurs = pd.concat([utilisateurs, nouvel_utilisateur], ignore_index=True)

    utilisateurs.to_csv(USERS_FILE, index=False, encoding="utf-8-sig")
    return True

def se_connecter(username, password):
    utilisateurs = lire_utilisateurs()
    utilisateur = utilisateurs.loc[utilisateurs["username"] == username]
    if not utilisateur.empty:
        sel = utilisateur["salt"].values[0]
        mot_de_passe_hache = utilisateur["password_hash"].values[0]
        if mot_de_passe_hache == hacher_mot_de_passe(password, sel):
            return True
    return False

# --- Classes principales de l'application ---
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gestion des utilisateurs")
        self.geometry("800x600")
        self.current_user = None
        self.frames = {}  # Stocke les frames
        self.show_frame(LoginPage)  # Lance la première frame

    def show_frame(self, frame_class, *args):
        print(f"Changement de page vers : {frame_class.__name__}")  # Debug
        for frame in self.frames.values():
            frame.destroy()  # Détruit les anciennes frames
        
        frame = frame_class(self, *args)  # Crée la nouvelle frame
        frame.pack(expand=True, fill="both")  # Affiche la frame
        self.frames[frame_class] = frame  # Stocke la frame

class RegisterPage(tk.Frame):
    def __init__(self, master, username, password):
        super().__init__(master)
        self.username = username
        self.password = password

        tk.Label(self, text="Créer un compte", font=("Arial", 16)).pack(pady=20)

        # Ajouter des champs pour les informations personnelles
        tk.Label(self, text="Nom d'utilisateur:").pack()
        self.entry_username = tk.Entry(self)
        self.entry_username.insert(0, self.username)  # Remplir avec le nom d'utilisateur de la page précédente
        self.entry_username.pack()

        tk.Label(self, text="Mot de passe:").pack()
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.insert(0, self.password)  # Remplir avec le mot de passe de la page précédente
        self.entry_password.pack()

        self.fields = {}
        for label in ["nom", "prénom", "adresse", "email", "téléphone"]:
            tk.Label(self, text=label + ":").pack()
            self.fields[label] = tk.Entry(self)
            self.fields[label].pack()

        tk.Button(self, text="Créer le compte", command=self.create_account).pack(pady=10)
        tk.Button(self, text="Retour", command=lambda: master.show_frame(LoginPage)).pack()

    def create_account(self):
        # Récupérer les informations du formulaire
        username = self.entry_username.get()
        password = self.entry_password.get()
        nom = self.fields["nom"].get()
        prenom = self.fields["prénom"].get()
        adresse = self.fields["adresse"].get()
        email = self.fields["email"].get()
        telephone = self.fields["téléphone"].get()

        # Appel de la fonction pour enregistrer l'utilisateur
        if enregistrer_utilisateur(username, password, nom, prenom, adresse, email, telephone):
            messagebox.showinfo("Succès", "Compte créé avec succès.")
            self.master.show_frame(LoginPage)
        else:
            messagebox.showerror("Erreur", "Erreur lors de la création du compte.")

class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Connexion / Inscription", font=("Arial", 16)).pack(pady=20)

        tk.Label(self, text="Nom d'utilisateur:").pack()
        self.entry_username = tk.Entry(self)
        self.entry_username.pack()

        tk.Label(self, text="Mot de passe:").pack()
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.pack()

        tk.Button(self, text="Se connecter", command=self.login).pack(pady=5)
        tk.Button(self, text="Créer un compte", command=self.register).pack(pady=5)

        # Ajout du bouton pour afficher/masquer le mot de passe
        self.var_show_password = tk.BooleanVar()
        tk.Checkbutton(self, text="Afficher le mot de passe", variable=self.var_show_password, command=self.toggle_password).pack(pady=5)

    def login(self):
        """Méthode pour la connexion de l'utilisateur"""
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Vérifiez si l'utilisateur existe et si le mot de passe est correct
        if se_connecter(username, password):
            messagebox.showinfo("Succès", "Connexion réussie.")
            self.master.current_user = username  # Vous pouvez ajouter l'utilisateur actuel à votre app
            self.master.show_frame(MenuPage)  # Remplacez MenuPage par la page après connexion
        else:
            messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect.")

    def toggle_password(self):
        """Affiche ou masque le mot de passe."""
        if self.var_show_password.get():
            self.entry_password.config(show="")
        else:
            self.entry_password.config(show="*")

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        self.master.show_frame(RegisterPage, username, password)


    def create_account(self):
        # Récupérer les informations du formulaire
        username = self.entry_username.get()
        password = self.entry_password.get()
        nom = self.fields["Nom"].get()
        prenom = self.fields["Prénom"].get()
        adresse = self.fields["Adresse"].get()
        email = self.fields["Email"].get()
        telephone = self.fields["Téléphone"].get()

        # Appel de la fonction pour enregistrer l'utilisateur
        if enregistrer_utilisateur(username, password, nom, prenom, adresse, email, telephone):
            messagebox.showinfo("Succès", "Compte créé avec succès.")
            self.master.show_frame(LoginPage)
        else:
            messagebox.showerror("Erreur", "Erreur lors de la création du compte.")

class MenuPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text=f"Bienvenue, {master.current_user} !", font=("Arial", 16)).pack(pady=20)
    
        tk.Button(self, text="Gestion des badges", command=lambda: master.show_frame(Gestion_Badge)).pack(pady=5)
        tk.Button(self, text="Créer des badges", command=lambda: master.show_frame(Creer_Badge)).pack(pady=5)
        tk.Button(self, text="supprimer des badges", command=lambda: master.show_frame(Supprimer_Badge)).pack(pady=5)
        tk.Button(self, text="Mon compte", command=lambda: master.show_frame(MonComptePage)).pack(pady=5)
        tk.Button(self, text="Déconnexion", command=lambda: master.show_frame(LoginPage)).pack(pady=5)

class Gestion_Badge(tk.Frame):
    def __init__(self, master):
        super().__init__(master)  

        tk.Label(self, text="Gestion des badges RFID", font=("Arial", 16)).pack(pady=10)

        tk.Label(self, text="ID du badge:").pack()
        self.entry_badge_id = tk.Entry(self)
        self.entry_badge_id.pack()

        tk.Label(self, text="Niveau de permission:").pack()
        self.permission_var = tk.StringVar(self)
        self.permission_var.set("user")
        tk.OptionMenu(self, self.permission_var, "user", "admin", "unauthorized").pack()

        tk.Button(self, text="Mettre à jour", command=self.update_permissions).pack(pady=5)

        # Bouton pour revenir au menu principal
        tk.Button(self, text="Retour", command=lambda: master.show_frame(MenuPage)).pack(pady=5)

    def get_jwt_token(self):
        """Récupère le jeton JWT pour l'API."""
        payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "",
            "client_id": "",
            "client_secret": ""
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'accept': 'application/json'}

        response = requests.post(TOKEN_URL, data=payload, headers=headers)

        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération du token: {response.status_code}")
            return None

    def update_permissions(self):
        """Met à jour les permissions du badge RFID via l'API."""
        try:
            badge_id = int(self.entry_badge_id.get())
            new_permission = self.permission_var.get()

            if new_permission not in ["user", "admin", "unauthorized"]:
                messagebox.showerror("Erreur", "La permission doit être 'user', 'admin' ou 'unauthorized'")
                return

            access_token = self.get_jwt_token()
            if not access_token:
                return

            data = {
                "badge_id": badge_id,
                "level": new_permission
            }

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            response = requests.patch(API_URL, json=data, headers=headers)

            if response.status_code == 200:
                messagebox.showinfo("Succès", f"Permissions du badge {badge_id} mises à jour en '{new_permission}'")
            elif response.status_code == 401:
                messagebox.showerror("Erreur", "Non authentifié. Veuillez vérifier votre token.")
            else:
                messagebox.showerror("Erreur", f"Erreur lors de la mise à jour: {response.status_code}")

        except ValueError:
            messagebox.showerror("Erreur", "L'ID du badge doit être un nombre entier valide")

class Creer_Badge(tk.Frame):
    def __init__(self, master):
        super().__init__(master)  

        tk.Label(self, text="Gestion des badges RFID", font=("Arial", 16)).pack(pady=10)

        tk.Label(self, text="ID du badge:").pack()
        self.entry_badge_id = tk.Entry(self)
        self.entry_badge_id.pack()

        tk.Label(self, text="Niveau de permission:").pack()
        self.permission_var = tk.StringVar(self)
        self.permission_var.set("user")
        tk.OptionMenu(self, self.permission_var, "user", "admin", "unauthorized").pack()

        tk.Button(self, text="Créer", command=self.update_permissions).pack(pady=5)

        # Bouton pour revenir au menu principal
        tk.Button(self, text="Retour", command=lambda: master.show_frame(MenuPage)).pack(pady=5)

    def get_jwt_token(self):
        """Récupère le jeton JWT pour l'API."""
        payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "",
            "client_id": "",
            "client_secret": ""
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'accept': 'application/json'}

        response = requests.post(TOKEN_URL, data=payload, headers=headers)

        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération du token: {response.status_code}")
            return None

    def update_permissions(self):
        """Crée un badge RFID avec le niveau de permission spécifié."""
        badge_id = self.entry_badge_id.get().strip()
        if not badge_id.isdigit():
            messagebox.showerror("Erreur", "L'ID du badge doit être un nombre entier valide")
            return
        
        new_permission = self.permission_var.get()
        if new_permission not in ["user", "admin", "unauthorized"]:
            messagebox.showerror("Erreur", "La permission doit être 'user', 'admin' ou 'unauthorized'")
            return

        access_token = self.get_jwt_token()
        if not access_token:
            return

        data = {
            "badge_id": int(badge_id),
            "level": new_permission
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(CREER_API, json=data, headers=headers)
            response.raise_for_status()  # Vérifie les erreurs HTTP

            messagebox.showinfo("Succès", f"Badge {badge_id} créé avec la permission '{new_permission}'")

        except requests.HTTPError as http_err:
            messagebox.showerror("Erreur", f"Erreur HTTP: {http_err}")
        except requests.RequestException as req_err:
            messagebox.showerror("Erreur", f"Erreur de connexion: {req_err}")
    
class Supprimer_Badge(tk.Frame):
    def __init__(self, master):
        super().__init__(master)  

        tk.Label(self, text="Gestion des badges RFID", font=("Arial", 16)).pack(pady=10)

        tk.Label(self, text="ID du badge:").pack()
        self.entry_badge_id = tk.Entry(self)
        self.entry_badge_id.pack()

        tk.Button(self, text="Supprimer", command=self.delete_badge).pack(pady=5)

        # Bouton pour revenir au menu principal
        tk.Button(self, text="Retour", command=lambda: master.show_frame(MenuPage)).pack(pady=5)

    def get_jwt_token(self):
        """Récupère le jeton JWT pour l'API."""
        username = "admin_123"
        password = "password_456"

        payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "",
            "client_id": "",
            "client_secret": ""
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json"
        }

        try:
            response = requests.post(TOKEN_URL, data=payload, headers=headers)
            response.raise_for_status()
            return response.json().get("access_token")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erreur", f"Échec de la récupération du token: {e}")
            return None

    def delete_badge(self):
        """Supprime un badge via l'API."""
        badge_id = self.entry_badge_id.get().strip()

        if not badge_id.isdigit():
            messagebox.showerror("Erreur", "L'ID du badge doit être un nombre entier valide")
            return

        access_token = self.get_jwt_token()
        if not access_token:
            return

        url = f"{DELETE_BADGE}?badge_id={badge_id}"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            messagebox.showinfo("Succès", f"Badge {badge_id} supprimé avec succès.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Erreur", f"Erreur lors de la suppression du badge: {e}")

class MonComptePage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        if master.current_user is None:
            messagebox.showerror("Erreur", "Vous devez être connecté pour accéder à cette page.")
            master.show_frame(LoginPage)
            return

        utilisateurs = lire_utilisateurs()
        utilisateurs.columns = utilisateurs.columns.str.strip()  # Nettoyage des noms de colonnes

        required_columns = {"Nom", "Prénom", "Adresse", "Email", "Téléphone"}
        if not required_columns.issubset(utilisateurs.columns):
            messagebox.showerror("Erreur", "Le fichier des utilisateurs est mal formaté.")
            return

        utilisateur = utilisateurs[utilisateurs["username"] == master.current_user]

        if utilisateur.empty:
            messagebox.showerror("Erreur", "Utilisateur non trouvé.")
            master.show_frame(LoginPage)
            return

        utilisateur = utilisateur.iloc[0]  # Récupération de la première ligne correspondant à l'utilisateur

        tk.Label(self, text="Mon Compte", font=("Arial", 16)).pack(pady=20)

        self.fields = {}  # Déclarer self.fields ici

        for label in ["Nom", "Prénom", "Adresse", "Email", "Téléphone"]:
            tk.Label(self, text=label + ":").pack()
            self.fields[label] = tk.Entry(self)
            self.fields[label].insert(0, utilisateur[label])  # Remplir avec les infos existantes
            self.fields[label].pack()

        tk.Button(self, text="Mettre à jour", command=self.mettre_a_jour).pack(pady=10)
        tk.Button(self, text="Retour", command=lambda: master.show_frame(MenuPage)).pack()

    def mettre_a_jour(self):
        """Met à jour les informations de l'utilisateur dans la base de données."""
        nom = self.fields["Nom"].get()
        prenom = self.fields["Prénom"].get()
        adresse = self.fields["Adresse"].get()
        email = self.fields["Email"].get()
        telephone = self.fields["Téléphone"].get()

        utilisateurs = lire_utilisateurs()
        index = utilisateurs[utilisateurs["username"] == self.master.current_user].index

        if not index.empty:
            utilisateurs.loc[index, ["Nom", "Prénom", "Adresse", "Email", "Téléphone"]] = [nom, prenom, adresse, email, telephone]
            utilisateurs.to_csv(USERS_FILE, index=False, encoding="utf-8-sig")
            messagebox.showinfo("Succès", "Informations mises à jour.")
        else:
            messagebox.showerror("Erreur", "Utilisateur non trouvé.")

# --- fonction de MonComptePage ---

def lire_utilisateurs():
    """Charge les utilisateurs depuis un fichier CSV."""
    try:
        return pd.read_csv(USERS_FILE)
    except FileNotFoundError:
        return pd.DataFrame(columns=["Nom", "Prénom", "Email"])

def sauvegarder_utilisateurs(utilisateurs):
    """Sauvegarde la liste des utilisateurs dans un fichier CSV."""
    utilisateurs.to_csv(USERS_FILE, index=False, encoding="utf-8-sig")

app = Application()
app.mainloop()