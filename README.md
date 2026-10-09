# Scanner d'appareils Wi-Fi (Windows)

## Ce que fait ce script
Liste les appareils actuellement connectés à ton réseau Wi-Fi/local :
- Adresse IP
- Adresse MAC
- Nom d'hôte (quand il est résolvable)

## Ce que ce script NE fait PAS
Il ne montre **pas** les sites web visités par chaque appareil. Voir le
trafic d'un appareil qui n'est pas le tien nécessite une interception de
communications (ARP spoofing / MITM), qui est une forme de surveillance
non autorisée si les personnes concernées n'ont pas donné leur accord
explicite — potentiellement illégal selon les pays. Ce script s'en tient
donc à la simple découverte réseau (ce que fait déjà un routeur dans son
interface d'administration).

## Prérequis
- Windows 10/11
- Python 3.8 ou plus récent installé (https://python.org)
- Aucune bibliothèque externe à installer

## Utilisation — version ligne de commande
1. Ouvre une invite de commandes (cmd ou PowerShell)
2. Place-toi dans le dossier du script :
   ```
   cd chemin\vers\scan_wifi
   ```
3. Lance :
   ```
   python scan_reseau.py
   ```
4. Le script ping toutes les IP de ton réseau local puis affiche la liste
   des appareils trouvés dans la table ARP de Windows.

## Utilisation — version interface graphique (recommandée)
Même moteur de scan, présenté dans une fenêtre avec tableau, thème sombre
et bouton de rafraîchissement. Tkinter est inclus avec Python, aucune
installation nécessaire.

```
python scan_reseau_gui.py
```

Le scan se lance automatiquement à l'ouverture. Clique sur "🔄 Rafraîchir"
pour relancer un scan à tout moment ; la barre de statut en bas affiche la
progression puis le nombre d'appareils trouvés.

## Utilisation — version page web (si Tkinter pose problème)
Même moteur de scan, affiché dans ton navigateur via un mini serveur web
local. Aucune dépendance externe (pas besoin de Tcl/Tk ni de Flask).

```
python scan_reseau_web.py
```

Le script démarre un serveur sur `http://localhost:8000` et ouvre ton
navigateur automatiquement. Clique sur "🔄 Rafraîchir" sur la page pour
relancer un scan. Laisse la fenêtre du terminal ouverte tant que tu
utilises la page (Ctrl+C dans le terminal pour arrêter le serveur).

## Alternative recommandée
Pour une vue plus fiable et plus riche (noms d'appareils, type, historique
de connexion), la plupart des box/routeurs Wi-Fi (Orange, Freebox, TP-Link,
etc.) ont une page d'administration (souvent http://192.168.1.1) listant
tous les appareils connectés — sans rien installer.

## Si le besoin réel est le contrôle parental
Si l'objectif est de superviser l'usage Internet d'enfants sur ton propre
réseau, préfère des solutions dédiées et transparentes : contrôle parental
intégré au routeur, Google Family Link, Microsoft Family Safety, etc.
