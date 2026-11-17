# API REST CyberTrack

API Node.js/Express 5 et Mongoose de CyberTrack. Elle utilise la base existante
`cybertrack_db`; elle ne réinitialise pas les collections et ne relance pas le
seed. Les modèles ciblent explicitement les cinq collections existantes.
Toutes les routes métier exigent une session authentifiée. La santé et les
routes de connexion sont publiques.

## Architecture

```text
server/
├── config/database.js          # Chargement .env et connexion Mongoose
├── controllers/                # Logique HTTP, filtres et agrégations
├── database/                   # Laboratoire mongosh et vérifications existants
├── docs/
│   ├── API_DOCUMENTATION.md
│   └── MONGODB_LAB.md
├── middleware/                 # Authentification, sécurité, erreurs et 404
├── models/                     # Schémas Mongoose des collections existantes
├── routes/                     # Routes REST versionnées sous /api
├── scripts/bootstrapAdmin.js   # Initialisation volontaire du compte admin
├── tests/api.test.js            # Tests d'intégration sur base éphémère
├── utils/                       # Validation, sérialisation et helpers
├── app.js
├── server.js
└── package.json
```

Les schémas désactivent `timestamps` et `versionKey`, car ces champs ne
correspondent pas au stockage existant. Les collections sont spécifiées
explicitement. Les références Mongoose reprennent les `ObjectId` réellement
présents; `scans.results` et `remediation_tasks.history` restent des sous-
documents intégrés.

## Installation et configuration

Node.js 24 et MongoDB local doivent être disponibles. Depuis PowerShell, à la
racine du projet, installer les dépendances :

```powershell
Set-Location .\server
npm install
```

Le fichier `server/.env.example` donne les noms de variables. Copiez-le en
`server/.env` seulement si ce dernier n'existe pas; ne remplacez pas une
configuration existante. `MONGODB_URI` doit viser la base `cybertrack_db` et
`JWT_SECRET` doit contenir au moins 32 octets aléatoires. Ne publiez ni `.env`
ni sa valeur. Les autres paramètres sont :

| Variable | Défaut | Description |
|---|---|---|
| `MONGODB_URI` | aucun | URI MongoDB; obligatoire, ne pas la journaliser. |
| `MONGODB_DATABASE` | `cybertrack_db` | Nom de base attendu par le backend. Le nom doit aussi correspondre à l'URI. |
| `JWT_SECRET` | aucun | Secret aléatoire d'au moins 32 octets; obligatoire au démarrage. |
| `HOST` | `127.0.0.1` | Interface d'écoute; loopback par défaut. |
| `PORT` | `5000` | Port HTTP, entier de 1 à 65535. |
| `CORS_ORIGIN` | `http://localhost:5173,http://127.0.0.1:5173` | Origine(s) frontend autorisée(s), séparées par des virgules. |
| `NODE_ENV` | dépend de Node | Mode d'exécution; les détails internes ne sont jamais renvoyés dans les erreurs 500. |

La connexion désactive la création automatique d'index Mongoose (`autoIndex:
false`) afin que le démarrage de l'API ne modifie pas les index installés par le
laboratoire.
L'index multikey `scan_result_vulnerability_index` sur
`scans.results.vulnerabilityId` est installé par `npm run db:indexes` pour
accélérer les vues de relations CVE/scans; `npm run db:verify` en vérifie la
présence.

## Démarrage et santé

Dans une fenêtre PowerShell :

```powershell
Set-Location .\server
npm run dev
```

Pour le mode normal, utiliser `npm start`. Le serveur attend la connexion à
MongoDB avant d'écouter. La sortie indique l'hôte et le port, jamais l'URI.
Vérifier dans une seconde fenêtre :

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/health
```

Réponse lorsque MongoDB est joignable :

```json
{
  "success": true,
  "data": {
    "status": "ok",
    "database": "connected"
  }
}
```

`Ctrl+C` arrête proprement le serveur et ferme la connexion MongoDB.

## Format de réponse et erreurs

Une réponse réussie utilise `success` et `data`; les listes contiennent aussi
les métadonnées `pagination`. Les erreurs utilisent le format suivant :

```json
{
  "success": false,
  "error": {
    "message": "Invalid id."
  }
}
```

Les erreurs de validation peuvent inclure `error.details`, une liste de champs
et messages sans contenu sensible. Statuts utilisés : `200` succès, `201`
création, `400` entrée invalide, `404` ressource/route absente, `409` doublon
ou référence empêchant la suppression, `500` erreur interne et `503` santé
indisponible. Les suppressions référencées sont refusées pour éviter de créer
des ObjectId orphelins. `passwordHash` et les mots de passe ne sont jamais sérialisés. Les erreurs 500
ne retournent ni URI de connexion ni détails internes.

## Authentification et rôles

| Méthode et route | Accès |
|---|---|
| `POST /api/auth/login` | Public; vérifie l'email et le mot de passe haché. |
| `POST /api/auth/logout` | Public; efface le cookie de session. |
| `GET /api/auth/me` | Session requise; renvoie l'utilisateur courant sans hash. |
| `GET /api/health` | Public; indique l'état HTTP et MongoDB, sans données métier. |

Après connexion, le serveur pose un JWT HS256 dans `cybertrack_token` avec
`HttpOnly`, `SameSite=Strict`, une durée de 15 minutes et `Secure` en mode
production. Le client doit conserver les cookies (Fetch `credentials:
"include"`). `CORS_ORIGIN` et la vérification d'origine limitent les requêtes
cross-origin. L'API applique Helmet, une limite de taille JSON, des limites de
requêtes et un contrôle des opérateurs NoSQL.

Les rôles sont `ADMIN`, `SECURITY_ANALYST` et `VIEWER`; les comptes historiques
`ANALYST` sont reconnus comme `SECURITY_ANALYST`. Tous les rôles actifs peuvent
lire les vulnérabilités, assets, scans, tâches et dashboard. Les rôles
`ADMIN` et `SECURITY_ANALYST` peuvent modifier les ressources métier; seul
`ADMIN` peut gérer les utilisateurs. Les utilisateurs sont relus en base à
chaque requête, donc désactivation et changement de rôle s'appliquent
immédiatement.

Les mots de passe sont hachés avec bcrypt (coût 12). L'API d'administration
accepte `password` lors de la création ou du changement de mot de passe et
refuse `passwordHash`. La longueur est de 12 à 128 caractères et au plus
72 octets UTF-8.

### Initialiser volontairement un administrateur

Le projet ne réinitialise pas automatiquement un compte ni les données. Pour
créer un administrateur ou promouvoir un compte existant, exécuter une seule
fois la commande suivante dans PowerShell depuis `server/`. Elle demande le
mot de passe sans l'afficher; sélectionner un email existant remplace son mot
de passe et son rôle :

```powershell
$env:BOOTSTRAP_ADMIN_EMAIL = Read-Host 'Email administrateur'
$securePassword = Read-Host 'Mot de passe (12 caractères minimum)' -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $env:BOOTSTRAP_ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    npm run auth:bootstrap
}
finally {
    Remove-Item Env:BOOTSTRAP_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:BOOTSTRAP_ADMIN_EMAIL -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    $securePassword.Dispose()
}
```

Le mot de passe doit aussi rester sous la limite bcrypt de 72 octets UTF-8.
Ne pas ajouter les variables `BOOTSTRAP_ADMIN_*` au fichier `.env`.

Connexion PowerShell avec cookie de session :

```powershell
$loginBody = @{
    email = 'admin@example.com'
    password = Read-Host 'Mot de passe'
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:5000/api/auth/login `
    -Method Post -ContentType 'application/json' -Body $loginBody `
    -SessionVariable CyberTrackSession
Invoke-RestMethod http://127.0.0.1:5000/api/auth/me `
    -WebSession $CyberTrackSession
Invoke-RestMethod http://127.0.0.1:5000/api/vulnerabilities `
    -WebSession $CyberTrackSession
```

Les contrôleurs n'acceptent que des champs explicitement autorisés. Les
paramètres de requête non reconnus, les tris non autorisés, les identifiants
invalides et les corps JSON incorrects sont rejetés.

## Vulnérabilités

### `GET /api/vulnerabilities`

Liste paginée. Paramètres :

| Paramètre | Règle |
|---|---|
| `page` | Entier ≥ 1; défaut `1`. |
| `limit` | Entier de 1 à 100; défaut `20`. |
| `q` | Recherche insensible à la casse dans `cveId` et `title`; maximum 120 caractères. Le texte est échappé avant la regex. |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM` ou `LOW`. |
| `status` | `ACTIVE`, `MITIGATED` ou `CLOSED`. |
| `minCvss`, `maxCvss` | Nombre entre 0 et 10; bornes inclusives et minimum ≤ maximum. |
| `publishedFrom`, `publishedTo` | Bornes inclusives `YYYY-MM-DD` sur `publishedAt`; début ≤ fin. |
| `sort` | `cvss`, `publishedAt`, `severity` ou `_id`; défaut `publishedAt`. |
| `order` | `asc` ou `desc`; défaut `desc`. |

Exemple PowerShell :

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/vulnerabilities?page=1&limit=5&severity=CRITICAL&minCvss=9&sort=cvss&order=desc'
```

La réponse comprend `data: [...]` et `pagination: { page, limit, total,
pages }`. Les documents exposent les champs de vulnérabilité présents dans la
collection.

Exemple de structure de réponse :

```json
{
  "success": true,
  "data": [
    {
      "_id": "ObjectId",
      "cveId": "CVE-2099-123456",
      "title": "Example vulnerability",
      "severity": "HIGH",
      "cvss": 8.1,
      "status": "ACTIVE"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 5,
    "total": 1,
    "pages": 1
  }
}
```

### Autres routes

| Méthode et route | Fonction |
|---|---|
| `GET /api/vulnerabilities/search?q=...` | Recherche obligatoire dans le CVE et le titre; accepte aussi pagination, filtres et tri ci-dessus. |
| `GET /api/vulnerabilities/stats` | Comptages et min/max/moyenne CVSS par sévérité via agrégation MongoDB. |
| `GET /api/vulnerabilities/:id` | Lire par ObjectId. |
| `GET /api/vulnerabilities/:id/related` | Assets concernés, scans correspondants et tâches de remédiation. |
| `POST /api/vulnerabilities` | ADMIN ou SECURITY_ANALYST; champs autorisés : `cveId`, `title`, `description`, `severity`, `cvss`, `cweIds`, `affectedProducts`, `publishedAt`, `lastModifiedAt`, `source`, `status`, `references`. |
| `PUT /api/vulnerabilities/:id` | Mise à jour partielle des champs autorisés. La validation Mongoose et la validation stricte MongoDB sont actives. |
| `DELETE /api/vulnerabilities/:id` | Supprimer si aucun scan ni tâche ne référence la vulnérabilité; sinon `409`. |

Exemple :

```powershell
$body = @{
    cveId = 'CVE-2099-123456'
    title = 'Example vulnerability'
    description = 'Example description'
    severity = 'HIGH'
    cvss = 8.1
    cweIds = @('CWE-79')
    affectedProducts = @('Example Product')
    publishedAt = '2026-01-15T12:00:00Z'
    lastModifiedAt = '2026-01-15T12:00:00Z'
    source = 'API'
    status = 'ACTIVE'
    references = @()
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:5000/api/vulnerabilities `
    -Method Post -ContentType 'application/json' -Body $body
```

L'index unique MongoDB sur `cveId` reste l'autorité en cas de doublon.

## Assets

Toutes les listes acceptent `page`, `limit`, `sort`, `order`. Les paramètres
facultatifs sont `q` (hostname, adresse IP ou propriétaire), `environment`,
`criticality`, `isActive` (`true`/`false`).

| Méthode et route | Fonction |
|---|---|
| `GET /api/assets` | Liste paginée. |
| `GET /api/assets/:id/related` | Scans, vulnérabilités trouvées et tâches associées à l'asset. |
| `GET /api/assets/:id` | Lire un asset. |
| `POST /api/assets` | Créer avec les champs du modèle : `hostname`, `ipAddress`, `assetType`, `operatingSystem`, `environment`, `criticality`, `tags`, `owner`, `createdAt`, `isActive`. |
| `PUT /api/assets/:id` | Mise à jour partielle par liste blanche. |
| `DELETE /api/assets/:id` | Supprimer seulement si aucun scan/tâche ne le référence. |

Tris disponibles : `hostname`, `createdAt`, `criticality`, `_id`.

Exemple :

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/assets?isActive=true&limit=10'
```

`data` est une liste d'assets et `pagination` contient `page`, `limit`,
`total` et `pages`.

## Import NVD

L'import officiel NVD est une commande explicite, pas un processus automatique
ni un scan réseau. Depuis `server/`, avec la base cible configurée :

```powershell
npm run nvd:import
```

Le script lit l'API CVE NVD 2.0 avec pagination (jusqu'à 2 000 résultats par
page), attend entre les pages, retente les réponses HTTP 429/5xx et erreurs
réseau, et accepte une clé facultative dans `NVD_API_KEY`. Les CVE valides
sont créées ou mises à jour; le statut de traitement existant est conservé.
Tout document ayant `source: CYBERTRACK_SIMULATED` est ignoré et n'est jamais
remplacé. Les entrées NVD sans description anglaise, dates ou score CVSS
valide sont comptées comme ignorées. Aucune donnée n'est supprimée.

L'import complet sans clé peut durer longtemps en raison des limites publiques
de l'API. Il est conseillé de l'exécuter volontairement pendant une fenêtre
appropriée; le résultat final indique les nombres lus, ajoutés, mis à jour et
ignorés. Les tests de pagination, reprises et protection des données
synthétiques utilisent des réponses HTTP simulées; ils ne lancent pas un
import live.

## Utilisateurs

| Méthode et route | Fonction |
|---|---|
| `GET /api/users` | ADMIN; liste paginée; filtre facultatif `q`, `role`, `isActive`. |
| `GET /api/users/assignees` | ADMIN et SECURITY_ANALYST; recherche paginée des comptes actifs par nom; renvoie uniquement le nom, le rôle et le département pour les sélecteurs d’assignation. |
| `GET /api/users/:id` | ADMIN; lire un utilisateur sans `passwordHash`. |
| `POST /api/users` | ADMIN; créer avec `fullName`, `email`, `password`, `role`, `department`, `isActive`. Le serveur hache le mot de passe. |
| `PUT /api/users/:id` | ADMIN; mise à jour partielle; un nouveau `password` est haché par le serveur. |
| `DELETE /api/users/:id` | Suppression refusée si l'utilisateur est référencé par un scan ou une tâche. |

Exemple de réponse utilisateur :

```json
{
  "success": true,
  "data": {
    "_id": "ObjectId",
    "fullName": "Example User",
    "email": "user@example.invalid",
    "role": "ANALYST",
    "department": "Security",
    "isActive": true
  }
}
```

## Scans

| Méthode et route | Fonction |
|---|---|
| `GET /api/scans` | Liste paginée; recherche `q` dans le type/statut et filtres `status`, `assetId`, `scannedBy`. |
| `GET /api/scans/:id` | Lit un scan et peuple asset, utilisateur et vulnérabilités des résultats. |
| `POST /api/scans` | Crée un scan; les références doivent exister et `results` conserve les sous-documents intégrés. |
| `PUT /api/scans/:id` | Mise à jour partielle validée. |
| `DELETE /api/scans/:id` | Supprime le scan. |

Tris disponibles : `startedAt`, `completedAt`, `status`, `_id`. Chaque résultat
intégré accepte `vulnerabilityId`, `port`, `protocol`, `status`,
`severitySnapshot`, `evidence` et `detectedAt`.

Exemple de lecture avec population :

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/scans?status=COMPLETED&limit=5'
```

Les champs `assetId`, `scannedBy` et `results[].vulnerabilityId` sont remplacés
par les documents associés dans les résultats peuplés. La projection user ne
comprend jamais `passwordHash`.

## Tâches de remédiation

Préfixe : `/api/remediation`.

| Méthode et route | Fonction |
|---|---|
| `GET /api/remediation` | Liste paginée; recherche `q` dans titre/description et filtres `status`, `priority`, `assignedTo`, `vulnerabilityId`. |
| `GET /api/remediation/:id` | Lit la tâche avec vulnérabilité, asset, assigné et créateur peuplés. |
| `POST /api/remediation` | Crée la tâche; les ObjectId référencés doivent exister. `createdBy` vient de la session et une entrée `CREATED` est générée. |
| `PUT /api/remediation/:id` | Mise à jour partielle; une entrée d'historique est générée pour les modifications. |
| `DELETE /api/remediation/:id` | Supprime la tâche. |

Tris disponibles : `createdAt`, `dueDate`, `priority`, `status`, `_id`. Une
entrée `history` contient `action`, `changedAt` et `note`.
Les champs `history`, `createdBy` et `completedAt` ne sont pas modifiables par
le client. Un changement vers `COMPLETED` définit `completedAt`; toute
transition hors de `COMPLETED` le remet à `null`. Les entrées d'historique
`STATUS_CHANGED` et `UPDATED` sont créées par l'API.

Exemple :

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/remediation?status=OPEN&priority=HIGH&limit=5'
```

La réponse paginée contient la tâche et les références peuplées
`vulnerabilityId`, `assetId`, `assignedTo` et `createdBy`.

## Dashboard

Les statistiques sont calculées dans MongoDB avec des pipelines d'agrégation;
les documents ne sont pas téléchargés en entier dans Node.js.

| Méthode et route | Réponse `data` |
|---|---|
| `GET /api/dashboard/overview` | Total vulnérabilités, comptes par sévérité, assets actifs, scans par état, tâches ouvertes/en retard/terminées. |
| `GET /api/dashboard/severity` | Liste `{ severity, count, averageCvss }`. |
| `GET /api/dashboard/vulnerability-status` | Comptages MongoDB par statut de vulnérabilité. |
| `GET /api/dashboard/monthly-trends` | Liste `{ year, month, count, averageCvss }` à partir de `publishedAt`. |
| `GET /api/dashboard/top-vulnerabilities` | Au plus 10 vulnérabilités triées par CVSS puis date. |
| `GET /api/dashboard/scans` | Nombre de scans, résultats intégrés et scans terminés par état. |
| `GET /api/dashboard/top-assets` | Au plus 10 assets triés par constats de scan, avec nombre de constats critiques. |
| `GET /api/dashboard/frequent-cves` | CVE les plus souvent observées dans les résultats des scans, avec occurrences et scans distincts. |

Exemple de requête et de réponse :

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/dashboard/severity
```

```json
{
  "success": true,
  "data": [
    { "severity": "CRITICAL", "count": 1073, "averageCvss": 9.52 }
  ]
}
```

Les pipelines effectuent les regroupements et jointures dans MongoDB. Les
constats des assets et les CVE fréquentes proviennent des résultats intégrés
des scans; un scan sans résultats n'augmente pas ces classements.

## Tests

Depuis `server/` :

```powershell
npm test
```

Le test d'intégration vérifie le démarrage Express, MongoDB, les routes de
lecture/écriture, filtres/pagination, login/logout, cookie HttpOnly, rôles,
erreurs, peuplement, hachage et absence de fuite des hashes, ainsi que toutes
les agrégations du dashboard. Il crée un nom de base aléatoire `cybertrack_api_test_*`,
vérifie qu'il est distinct de `cybertrack_db`, puis supprime uniquement cette
base temporaire. Avant et après la suite, il compare le nombre de vulnérabilités
et les noms des collections de production. Il échoue si les 10 001 documents
initiaux ou les cinq collections ont changé.

Vérifier séparément le laboratoire MongoDB sans modifier ses données :

```powershell
npm run db:verify
```
