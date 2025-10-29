# 🚀 HttpHeaderInspector


**WinToolsSuite – Security Tools for Network & Pentest**
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training

---

## 📋 Description

**HttpHeaderInspector** interroge des URLs HTTP/HTTPS et analyse les headers de réponse pour identifier des configurations de sécurité faibles ou absentes. L'outil vérifie la présence de headers critiques comme HSTS, CSP, X-Frame-Options et X-Content-Type-Options.

### Fonctionnalités principales

- **Requête HTTP/HTTPS** : support protocoles via WinHTTP
- **Analyse headers** : détection automatique headers de sécurité
- **Détection vulnérabilités** : signale headers manquants
- **Status code** : affiche code réponse HTTP
- **Server banner** : identifie serveur web
- **Export CSV** : sauvegarde résultats d'audit

- --


## 📌 Prérequis

- Windows 10 / Windows Server 2016+ (x64)
- Visual Studio 2017+ avec outils C++
- Accès réseau (Internet ou intranet selon cibles)

- --


## Compilation

```bat
cd WinToolsSuite\HttpHeaderInspector
go.bat
```

- --


## 🚀 Utilisation

1. **Lancer** : `HttpHeaderInspector.exe`
2. **Entrer URL** : saisir URL complète (https://www.example.com)
3. **Scanner** : cliquer "Scanner"
4. **Consulter résultats** : ListView affiche headers et notes
5. **Exporter** : bouton "Exporter CSV"

### Interface

- **Champ URL** : saisie adresse cible
- **Bouton Scanner** : lance analyse
- **ListView colonnes** :
  - URL
  - Status : code HTTP (200, 404, etc.)
  - Server : banner serveur
  - Headers Sécurité : liste headers présents
  - Notes : warnings/recommandations

- --


## Headers Vérifiés

| Header | But | Recommandation |
|--------|-----|----------------|
| **Strict-Transport-Security** (HSTS) | Force HTTPS | max-age=31536000; includeSubDomains |
| **Content-Security-Policy** (CSP) | Prévient XSS | default-src 'self' |
| **X-Frame-Options** | Prévient clickjacking | DENY ou SAMEORIGIN |
| **X-Content-Type-Options** | Prévient MIME sniffing | nosniff |

- --


## Interprétation Résultats

### Tous headers présents
✅ Configuration sécurisée

### Headers manquants
⚠️ **Risques** :
- Pas de HSTS : attaques SSL strip possibles
- Pas de CSP : vulnérabilités XSS non atténuées
- Pas de X-Frame-Options : risque clickjacking
- Pas de X-Content-Type-Options : MIME confusion

- --


## Environnement LAB-CONTROLLED

### Configuration serveur test

**IIS (Windows Server)** :

1. Installer IIS avec module "URL Rewrite"
2. Ajouter headers via `web.config` :

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      <add name="Content-Security-Policy" value="default-src 'self'" />
      <add name="X-Frame-Options" value="DENY" />
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

3. Tester avec HttpHeaderInspector : `https://localhost`

**Apache (XAMPP/WAMP)** :

Ajouter à `.htaccess` :
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
```

- --


## Logs

Fichier : `%TEMP%\WinTools_HttpHeaderInspector_log.txt`

- --


## Limitations

- **Un URL à la fois** : pas de scan batch (TODO)
- **Pas de cookies** : analyse cookies non implémentée (TODO)
- **Pas de certificats SSL** : vérification cert non incluse (voir TlsCertInventory)

- --


## 🔒 Sécurité & Éthique

⚠️ **Scanner uniquement sites autorisés**

- Ne pas scanner des sites tiers sans autorisation
- Respecter robots.txt et politiques serveur
- Usage audit/pentest autorisé uniquement

- --


## Support

**Ayi NEDJIMI Consultants**
https://www.ayinedjimi-consultants.fr

- --


## 📄 Licence

MIT License - Voir `LICENSE.txt`


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>