"""
Scanner d'appareils Wi-Fi — Interface graphique (Windows)
-----------------------------------------------------------
Même moteur de scan que scan_reseau.py, avec une interface
graphique de bureau (Tkinter, inclus dans Python — rien à installer).

Usage :
    python scan_reseau_gui.py
"""

import subprocess
import socket
import re
import ipaddress
import concurrent.futures
import sys
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime


# ---------------------------------------------------------------------------
# Logique de scan (identique à scan_reseau.py)
# ---------------------------------------------------------------------------

def get_local_ip_et_masque():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_locale = s.getsockname()[0]
    finally:
        s.close()
    reseau = ipaddress.ip_network(ip_locale + "/24", strict=False)
    return ip_locale, reseau


def ping(ip):
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", "300", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def ping_sweep(reseau, on_progress=None):
    ips = list(reseau.hosts())
    total = len(ips)
    fait = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping, ip) for ip in ips]
        for _ in concurrent.futures.as_completed(futures):
            fait += 1
            if on_progress:
                on_progress(fait, total)


def lire_table_arp():
    resultat = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    sortie = resultat.stdout
    appareils = []
    ignorer = {"ff-ff-ff-ff-ff-ff"}
    motif = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)"
    )
    for ligne in sortie.splitlines():
        m = motif.search(ligne)
        if m:
            ip, mac, type_entree = m.groups()
            mac_l = mac.lower()
            if mac_l in ignorer or mac_l.startswith("01-00-5e"):
                continue
            if type_entree.lower() in ("static", "statique"):
                continue
            appareils.append({"ip": ip, "mac": mac})
    return appareils


def resoudre_nom_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resoudre_nom_netbios(ip, timeout=1.5):
    try:
        resultat = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=timeout
        )
        for ligne in resultat.stdout.splitlines():
            m = re.match(r"\s*([^\s<]+)\s*<00>\s+UNIQUE", ligne)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None


def resoudre_nom(ip):
    return resoudre_nom_dns(ip) or resoudre_nom_netbios(ip) or "Inconnu"


# ---------------------------------------------------------------------------
# Interface graphique
# ---------------------------------------------------------------------------

COULEUR_FOND = "#1e1f26"
COULEUR_PANNEAU = "#262830"
COULEUR_ACCENT = "#4f8cff"
COULEUR_TEXTE = "#e6e6e6"
COULEUR_TEXTE_FADE = "#9aa0ad"


class AppScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scanner Réseau — Appareils Wi-Fi")
        self.geometry("820x520")
        self.configure(bg=COULEUR_FOND)
        self.minsize(700, 420)

        self._construire_style()
        self._construire_interface()
        self.apres(200, self.lancer_scan)  # premier scan au démarrage

    # -- utilitaire pour exécuter sur le thread UI depuis un thread de fond
    def apres(self, delai_ms, fonction, *args):
        self.after(delai_ms, lambda: fonction(*args))

    def _construire_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=COULEUR_PANNEAU,
            fieldbackground=COULEUR_PANNEAU,
            foreground=COULEUR_TEXTE,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#2f323c",
            foreground=COULEUR_TEXTE,
            font=("Segoe UI Semibold", 10),
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", COULEUR_ACCENT)])

        style.configure(
            "Accent.TButton",
            background=COULEUR_ACCENT,
            foreground="white",
            font=("Segoe UI Semibold", 10),
            padding=8,
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", "#3b73e0")])

    def _construire_interface(self):
        # --- En-tête ---
        entete = tk.Frame(self, bg=COULEUR_FOND)
        entete.pack(fill="x", padx=24, pady=(20, 10))

        tk.Label(
            entete,
            text="Appareils connectés au réseau",
            bg=COULEUR_FOND,
            fg=COULEUR_TEXTE,
            font=("Segoe UI Semibold", 16),
        ).pack(side="left")

        self.bouton_scan = ttk.Button(
            entete, text="🔄  Rafraîchir", style="Accent.TButton",
            command=self.lancer_scan,
        )
        self.bouton_scan.pack(side="right")

        # --- Sous-titre / infos réseau ---
        self.label_reseau = tk.Label(
            self, text="Détection du réseau...",
            bg=COULEUR_FOND, fg=COULEUR_TEXTE_FADE, font=("Segoe UI", 9),
        )
        self.label_reseau.pack(fill="x", padx=24, anchor="w")

        # --- Tableau ---
        cadre_table = tk.Frame(self, bg=COULEUR_FOND)
        cadre_table.pack(fill="both", expand=True, padx=24, pady=14)

        colonnes = ("ip", "mac", "nom")
        self.table = ttk.Treeview(
            cadre_table, columns=colonnes, show="headings", selectmode="browse"
        )
        self.table.heading("ip", text="Adresse IP")
        self.table.heading("mac", text="Adresse MAC")
        self.table.heading("nom", text="Nom de l'appareil")
        self.table.column("ip", width=150, anchor="w")
        self.table.column("mac", width=190, anchor="w")
        self.table.column("nom", width=300, anchor="w")

        defilement = ttk.Scrollbar(cadre_table, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=defilement.set)
        self.table.pack(side="left", fill="both", expand=True)
        defilement.pack(side="right", fill="y")

        # --- Barre de statut ---
        pied = tk.Frame(self, bg=COULEUR_PANNEAU, height=30)
        pied.pack(fill="x", side="bottom")
        self.label_statut = tk.Label(
            pied, text="Prêt.", bg=COULEUR_PANNEAU, fg=COULEUR_TEXTE_FADE,
            font=("Segoe UI", 9), anchor="w",
        )
        self.label_statut.pack(fill="x", padx=14, pady=5)

    # -----------------------------------------------------------------
    def lancer_scan(self):
        self.bouton_scan.state(["disabled"])
        self.table.delete(*self.table.get_children())
        self.label_statut.config(text="Scan en cours...")
        threading.Thread(target=self._scan_en_arriere_plan, daemon=True).start()

    def _scan_en_arriere_plan(self):
        ip_locale, reseau = get_local_ip_et_masque()
        self.after(0, self.label_reseau.config, {
            "text": f"IP locale : {ip_locale}   |   Plage : {reseau}"
        })

        def progression(fait, total):
            pourcentage = int(fait / total * 100)
            self.after(0, self.label_statut.config, {
                "text": f"Scan en cours... {pourcentage}% ({fait}/{total})"
            })

        ping_sweep(reseau, on_progress=progression)
        appareils = lire_table_arp()

        self.after(0, self.label_statut.config, {"text": "Résolution des noms..."})
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            noms = list(executor.map(lambda a: resoudre_nom(a["ip"]), appareils))

        self.after(0, self._afficher_resultats, appareils, noms)

    def _afficher_resultats(self, appareils, noms):
        for a, nom in zip(appareils, noms):
            self.table.insert("", "end", values=(a["ip"], a["mac"], nom))

        heure = datetime.now().strftime("%H:%M:%S")
        if appareils:
            texte = f"{len(appareils)} appareil(s) trouvé(s) — dernier scan à {heure}"
        else:
            texte = f"Aucun appareil trouvé — dernier scan à {heure}. Réessaie dans quelques secondes."
        self.label_statut.config(text=texte)
        self.bouton_scan.state(["!disabled"])


def main():
    if not sys.platform.startswith("win"):
        print("Cette interface est prévue pour Windows (utilise 'arp'/'nbtstat').")
    app = AppScanner()
    app.mainloop()


if __name__ == "__main__":
    main()
