"""
Scanner d'appareils Wi-Fi — Interface web locale (Windows)
-------------------------------------------------------------
Même moteur de scan que scan_reseau.py, affiché dans une page web
stylée. Aucune dépendance externe : utilise uniquement le serveur
web intégré à Python (http.server), donc rien à installer.

Usage :
    python scan_reseau_web.py
    puis ouvre http://localhost:8000 dans ton navigateur
"""

import subprocess
import socket
import re
import ipaddress
import concurrent.futures
import sys
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8000


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


def ping_sweep(reseau):
    ips = list(reseau.hosts())
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(ping, ips))


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


def effectuer_scan():
    """Lance un scan complet et renvoie (ip_locale, reseau, liste_appareils)."""
    ip_locale, reseau = get_local_ip_et_masque()
    ping_sweep(reseau)
    appareils = lire_table_arp()
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        noms = list(executor.map(lambda a: resoudre_nom(a["ip"]), appareils))
    for a, nom in zip(appareils, noms):
        a["nom"] = nom
    return ip_locale, reseau, appareils


# ---------------------------------------------------------------------------
# Génération de la page HTML
# ---------------------------------------------------------------------------

def generer_page_html(ip_locale, reseau, appareils):
    heure = datetime.now().strftime("%H:%M:%S")

    if appareils:
        lignes = "\n".join(
            f"""
            <tr>
                <td>{a['ip']}</td>
                <td><code>{a['mac']}</code></td>
                <td>{a['nom']}</td>
            </tr>"""
            for a in appareils
        )
    else:
        lignes = """
            <tr>
                <td colspan="3" class="vide">Aucun appareil trouvé. Clique sur Rafraîchir.</td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner Réseau Wi-Fi</title>
<style>
    :root {{
        --fond: #1e1f26;
        --panneau: #262830;
        --accent: #4f8cff;
        --texte: #e6e6e6;
        --texte-faible: #9aa0ad;
        --bordure: #343744;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: var(--fond);
        color: var(--texte);
        padding: 32px 24px;
    }}
    .conteneur {{ max-width: 900px; margin: 0 auto; }}
    header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
        flex-wrap: wrap;
        gap: 12px;
    }}
    h1 {{ font-size: 1.5rem; margin: 0; font-weight: 600; }}
    .sous-titre {{ color: var(--texte-faible); font-size: 0.85rem; margin-bottom: 22px; }}
    .bouton {{
        background: var(--accent);
        color: white;
        border: none;
        padding: 10px 18px;
        border-radius: 8px;
        font-size: 0.9rem;
        font-weight: 600;
        cursor: pointer;
        text-decoration: none;
        display: inline-block;
        transition: background 0.15s ease;
    }}
    .bouton:hover {{ background: #3b73e0; }}
    .panneau {{
        background: var(--panneau);
        border: 1px solid var(--bordure);
        border-radius: 12px;
        overflow: hidden;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
        text-align: left;
        padding: 12px 16px;
        font-size: 0.9rem;
    }}
    th {{
        background: #2f323c;
        color: var(--texte-faible);
        font-weight: 600;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }}
    tbody tr {{ border-top: 1px solid var(--bordure); }}
    tbody tr:hover {{ background: #2b2e38; }}
    td code {{ color: #8fb4ff; font-size: 0.85rem; }}
    .vide {{ text-align: center; color: var(--texte-faible); padding: 30px; }}
    .pied {{
        margin-top: 14px;
        color: var(--texte-faible);
        font-size: 0.8rem;
        display: flex;
        justify-content: space-between;
    }}
    .badge {{
        background: #2f323c;
        color: var(--texte-faible);
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.78rem;
    }}
</style>
</head>
<body>
<div class="conteneur">
    <header>
        <h1>📡 Appareils connectés au réseau</h1>
        <a href="/scan" class="bouton">🔄 Rafraîchir</a>
    </header>
    <div class="sous-titre">IP locale : {ip_locale} &nbsp;•&nbsp; Plage analysée : {reseau}</div>

    <div class="panneau">
        <table>
            <thead>
                <tr>
                    <th>Adresse IP</th>
                    <th>Adresse MAC</th>
                    <th>Nom de l'appareil</th>
                </tr>
            </thead>
            <tbody>{lignes}
            </tbody>
        </table>
    </div>

    <div class="pied">
        <span class="badge">{len(appareils)} appareil(s) trouvé(s)</span>
        <span>Dernier scan à {heure}</span>
    </div>
</div>
</body>
</html>"""


def generer_page_chargement():
    return """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Scan en cours...</title>
<style>
    body {
        margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center;
        background: #1e1f26; color: #e6e6e6; font-family: 'Segoe UI', sans-serif;
    }
    .msg { text-align: center; }
    .spin {
        width: 36px; height: 36px; border: 4px solid #343744; border-top-color: #4f8cff;
        border-radius: 50%; margin: 0 auto 16px; animation: tourner 0.8s linear infinite;
    }
    @keyframes tourner { to { transform: rotate(360deg); } }
</style>
</head>
<body>
    <div class="msg">
        <div class="spin"></div>
        Scan du réseau en cours (quelques secondes)...
    </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Serveur HTTP
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence les logs par défaut dans le terminal

    def _envoyer_html(self, html):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        if self.path in ("/", "/scan"):
            ip_locale, reseau, appareils = effectuer_scan()
            html = generer_page_html(ip_locale, reseau, appareils)
            self._envoyer_html(html)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    if not sys.platform.startswith("win"):
        print("Ce script est prévu pour Windows (utilise 'arp'/'nbtstat').")

    url = f"http://localhost:{PORT}"
    print(f"Serveur démarré : {url}")
    print("Ouverture du navigateur... (laisse cette fenêtre ouverte)")
    print("Ctrl+C pour arrêter le serveur.\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    serveur = HTTPServer(("localhost", PORT), Handler)
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
        serveur.server_close()


if __name__ == "__main__":
    main()
