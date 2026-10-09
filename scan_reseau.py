"""
Scanner d'appareils connectés au Wi-Fi (Windows)
--------------------------------------------------
Liste les appareils actifs sur le réseau local : adresse IP,
adresse MAC et nom d'hôte (si résolvable).

Fonctionnement :
1. Détecte automatiquement la plage IP locale (ex: 192.168.1.0/24)
2. Fait un "ping sweep" pour forcer chaque appareil actif à apparaître
   dans la table ARP de Windows
3. Lit la table ARP (commande `arp -a`) et affiche les résultats
4. Tente une résolution DNS inverse pour retrouver le nom de l'appareil

Prérequis : Python 3.8+, aucune dépendance externe (tout est dans
la bibliothèque standard).

Usage :
    python scan_reseau.py
"""

import subprocess
import socket
import re
import ipaddress
import concurrent.futures
import sys


def get_local_ip_et_masque():
    """Récupère l'IP locale de la machine pour déduire la plage réseau."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_locale = s.getsockname()[0]
    finally:
        s.close()
    # Hypothèse réseau domestique classique : masque /24
    reseau = ipaddress.ip_network(ip_locale + "/24", strict=False)
    return ip_locale, reseau


def ping(ip):
    """Ping une IP une seule fois (silencieux), compatible Windows."""
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", "300", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def ping_sweep(reseau):
    """Ping toutes les IP de la plage en parallèle pour peupler la table ARP."""
    ips = [ip for ip in reseau.hosts()]
    print(f"Scan de {len(ips)} adresses sur {reseau}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping, ips)


def lire_table_arp(debug=False):
    """Parse la sortie de `arp -a` pour extraire IP + MAC."""
    resultat = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    sortie = resultat.stdout

    if debug:
        print("\n----- Sortie brute de 'arp -a' -----")
        print(sortie)
        print("----- Fin sortie brute -----\n")

    appareils = []
    adresses_a_ignorer = {"ff-ff-ff-ff-ff-ff"}  # broadcast
    # Format typique d'une ligne Windows : "  192.168.1.5   d8-3a-dd-xx-xx-xx   dynamique"
    motif = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)"
    )
    for ligne in sortie.splitlines():
        m = motif.search(ligne)
        if m:
            ip, mac, type_entree = m.groups()
            mac_l = mac.lower()
            if mac_l in adresses_a_ignorer:
                continue
            if mac_l.startswith("01-00-5e"):  # multicast, pas un vrai appareil
                continue
            # On ignore seulement les entrées explicitement statiques (FR/EN),
            # tout le reste (dynamic/dynamique/autre) est conservé.
            if type_entree.lower() in ("static", "statique"):
                continue
            appareils.append({"ip": ip, "mac": mac})
    return appareils


def resoudre_nom_dns(ip):
    """Essaie de retrouver le nom d'hôte via DNS inverse."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resoudre_nom_netbios(ip, timeout=1.5):
    """
    Essaie de retrouver le nom via NetBIOS (commande Windows `nbtstat -A`).
    Marche souvent même quand le DNS inverse échoue, pour les appareils
    Windows/anciens sur le réseau local.
    """
    try:
        resultat = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for ligne in resultat.stdout.splitlines():
            # Ligne typique : "MONPC           <00>  UNIQUE      Registered"
            m = re.match(r"\s*([^\s<]+)\s*<00>\s+UNIQUE", ligne)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None


def resoudre_nom(ip):
    """Combine DNS inverse et NetBIOS ; renvoie le premier résultat trouvé."""
    nom = resoudre_nom_dns(ip)
    if nom:
        return nom
    nom = resoudre_nom_netbios(ip)
    if nom:
        return nom
    return "Inconnu"


def main():
    if not sys.platform.startswith("win"):
        print("Ce script est prévu pour Windows (utilise 'arp -a').")

    ip_locale, reseau = get_local_ip_et_masque()
    print(f"IP locale détectée : {ip_locale}")
    print(f"Plage réseau analysée : {reseau}\n")

    ping_sweep(reseau)
    appareils = lire_table_arp()

    if not appareils:
        print("Aucun appareil trouvé via le filtre habituel.")
        print("Affichage de la table ARP brute pour diagnostic :\n")
        lire_table_arp(debug=True)
        return

    print(f"\n{len(appareils)} appareil(s) trouvé(s), résolution des noms...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        noms = list(executor.map(lambda a: resoudre_nom(a["ip"]), appareils))

    print(f"{'IP':<16} {'MAC':<20} {'Nom d’hôte'}")
    print("-" * 60)
    for a, nom in zip(appareils, noms):
        print(f"{a['ip']:<16} {a['mac']:<20} {nom}")


if __name__ == "__main__":
    main()
