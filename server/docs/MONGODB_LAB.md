# Laboratoire MongoDB avancé — CyberTrack

Ce laboratoire utilise la base locale `cybertrack_db` et les collections
`vulnerabilities`, `assets`, `users`, `scans` et `remediation_tasks`. Il ne
recrée pas la base et les scripts d'indexation, de validation et de vérification
ne suppriment ni ne régénèrent les données. Le script `seed.js` refuse désormais
de s'exécuter si la collection des vulnérabilités n'est pas vide.

## 1. État de départ vérifié

Lors de la préparation du laboratoire, MongoDB répondait et contenait :

| Collection | Documents observés |
|---|---:|
| `vulnerabilities` | 10 001 |
| `assets` | 1 |
| `users` | 1 |
| `scans` | 1 |
| `remediation_tasks` | 1 |

Les vulnérabilités ont les champs `cveId`, `title`, `description`, `severity`,
`cvss`, `cweIds`, `affectedProducts`, `publishedAt`, `lastModifiedAt`,
`source`, `status` et `references`. Un résultat de scan est intégré dans
`scans.results`; l'historique d'une tâche est intégré dans
`remediation_tasks.history`. Les autres relations utilisent des `ObjectId`.

Une validation stricte existait déjà. Le script la conserve et ajoute la
contrainte de chaîne non vide pour `cveId` et `title`; il pré-vérifie les
documents et les doublons avant toute modification. Les index principaux
étaient également déjà présents. Le script d'indexation les vérifie et ajoute
seulement les index de référence manquants.

## 2. Notions, syntaxe et exemples

Les exemples interactifs complets et réutilisables sont dans
[`database/queries.js`](../database/queries.js) et
[`database/relationships.js`](../database/relationships.js). Les blocs
ci-dessous sont exécutables dans `mongosh` après avoir sélectionné la base :

```javascript
use cybertrack_db
```

### `find()` et filtres

- **Définition :** `find()` sélectionne les documents correspondant à un
  filtre. Un filtre vide `{}` correspond à tous les documents.
- **Syntaxe :** `db.collection.find(filtre, projection)`.
- **CyberTrack :** obtenir les vulnérabilités critiques à traiter.
- **Exemple :**

  ```javascript
  db.vulnerabilities.find({ severity: "CRITICAL" })
  ```

- **Résultat attendu :** un curseur de documents contenant les champs stockés,
  notamment `cveId`, `title`, `severity` et `cvss`.
- **À expliquer à l'oral :** le filtre est évalué par MongoDB et `find()` ne
  transforme pas les documents comme le ferait un pipeline d'agrégation.

### Projection

- **Définition :** la projection choisit les champs renvoyés; elle n'efface ni
  ne modifie les champs enregistrés.
- **Syntaxe :** `find(filtre, { champ: 1, autre: 1, _id: 0 })`.
- **CyberTrack :** limiter les informations transférées au tableau CVE.
- **Exemple :**

  ```javascript
  db.vulnerabilities.find(
    { severity: "CRITICAL" },
    { _id: 0, cveId: 1, title: 1, cvss: 1 }
  )
  ```

- **Résultat attendu :** des documents `{ cveId, title, cvss }`.
- **À expliquer à l'oral :** inclusion et exclusion ne se mélangent pas, sauf
  pour `_id`.

### Tri et limite

- **Définition :** `sort()` trie le curseur (`1` ascendant, `-1` descendant);
  `limit()` borne le nombre de documents renvoyés.
- **Syntaxe :** `find(...).sort({ champ: -1 }).limit(n)`.
- **CyberTrack :** afficher cinq vulnérabilités critiques par score décroissant.
- **Exemple :**

  ```javascript
  db.vulnerabilities.find(
    { severity: "CRITICAL" },
    { _id: 0, cveId: 1, cvss: 1 }
  ).sort({ cvss: -1 }).limit(5)
  ```

- **Résultat attendu :** au plus cinq documents, du score le plus élevé au
  moins élevé.
- **À expliquer à l'oral :** le tri peut exploiter un index compatible; la
  limite réduit le volume renvoyé, mais ne garantit pas seule une lecture peu
  coûteuse.

### Opérateurs de filtre

Tous ces exemples retournent des documents de vulnérabilité; les valeurs
renvoyées dépendent des données présentes.

| Opérateur | Définition et syntaxe | Usage et exemple | Structure attendue / oral |
|---|---|---|---|
| `$gt` | Strictement supérieur : `{ cvss: { $gt: 9 } }` | Très haut risque : `db.vulnerabilities.find({ cvss: { $gt: 9 } }, { _id: 0, cveId: 1, cvss: 1 })` | `{ cveId, cvss }`; 9 lui-même est exclu. |
| `$gte` | Supérieur ou égal : `{ cvss: { $gte: 7 } }` | Inclure la borne basse : `db.vulnerabilities.find({ cvss: { $gte: 7, $lt: 9 } })` | CVSS dans `[7, 9[`; `$gte` inclut 7. |
| `$lt` | Strictement inférieur : `{ cvss: { $lt: 9 } }` | Utilisé ci-dessus pour borner la plage. | La borne haute 9 est exclue. |
| `$in` | Égal à l'une des valeurs : `{ severity: { $in: ["CRITICAL", "HIGH"] } }` | File de remédiation prioritaire. | Documents de sévérité CRITICAL ou HIGH. |
| `$ne` | Différent de la valeur : `{ status: { $ne: "CLOSED" } }` | Écarter les vulnérabilités clôturées. | Rappeler qu'un champ absent peut aussi satisfaire `$ne`. |
| `$regex` | Correspondance de motif : `{ title: { $regex: "nginx", $options: "i" } }` | Recherche insensible à la casse dans les titres. | `{ cveId, title }`; une regex non ancrée peut exiger un parcours important. |
| `$elemMatch` | Au moins un élément d'un tableau satisfait tous les critères : `{ results: { $elemMatch: {...} } }` | `db.scans.find({ results: { $elemMatch: { severitySnapshot: "CRITICAL", port: { $gte: 1 } } } })` | Un scan avec un même résultat critique et un port valide; sans `$elemMatch`, deux éléments pourraient satisfaire séparément les conditions. |

### Pipeline d'agrégation et étapes

- **Définition :** `aggregate()` fait passer les documents à travers une suite
  ordonnée d'étapes. Chaque étape reçoit le résultat de la précédente.
- **Syntaxe :** `db.collection.aggregate([ { $match: ... }, ... ])`.
- **CyberTrack :** produire des statistiques de vulnérabilités ou enrichir un
  scan avec ses relations.
- **Exemple combiné :**

  ```javascript
  db.vulnerabilities.aggregate([
    { $match: { cvss: { $gte: 0, $lte: 10 } } },
    {
      $group: {
        _id: "$severity",
        count: { $sum: 1 },
        averageCvss: { $avg: "$cvss" },
        minCvss: { $min: "$cvss" },
        maxCvss: { $max: "$cvss" }
      }
    },
    {
      $project: {
        _id: 0, severity: "$_id", count: 1,
        averageCvss: 1, minCvss: 1, maxCvss: 1
      }
    },
    { $sort: { count: -1 } },
    { $limit: 4 }
  ])
  ```

- **Résultat attendu :** au plus quatre documents
  `{ severity, count, averageCvss, minCvss, maxCvss }`.
- **À expliquer à l'oral :** l'ordre des étapes est important; réduire tôt les
  données avec `$match` est généralement préférable.

| Étape ou expression | Définition, syntaxe et utilité CyberTrack | Exemple exécutable | Résultat et oral |
|---|---|---|---|
| `$match` | Filtre les documents comme un filtre `find`; à placer tôt pour réduire le pipeline. | `{ $match: { severity: "CRITICAL" } }` | Seuls les documents critiques continuent. |
| `$group` | Regroupe selon `_id` et calcule une valeur par groupe. | `{ $group: { _id: "$severity", count: { $sum: 1 } } }` | Un document par sévérité; `_id` représente la clé de groupe. |
| `$project` | Construit, renomme ou masque les champs de sortie. | `{ $project: { _id: 0, severity: "$_id", count: 1 } }` | `{ severity, count }`; ne modifie pas la collection. |
| `$sort` | Trie les documents du pipeline. | `{ $sort: { count: -1 } }` | Le groupe le plus fréquent en premier. |
| `$limit` | Garde les premiers documents du pipeline. | `{ $limit: 4 }` | Au plus quatre groupes; son emplacement change le résultat. |
| `$sum` | Accumulateur de somme; `1` permet de compter les documents d'un groupe. | `count: { $sum: 1 }` | Nombre d'éléments; utile pour un tableau de bord. |
| `$avg` | Accumulateur de moyenne. | `averageCvss: { $avg: "$cvss" }` | Score moyen par sévérité. |
| `$min` / `$max` | Accumulateurs de minimum et de maximum. | `minCvss: { $min: "$cvss" }, maxCvss: { $max: "$cvss" }` | Bornes observées des scores par groupe. |
| `$year` / `$month` | Extrait l'année et le mois d'une date BSON dans une expression d'agrégation. | `{ $group: { _id: { year: { $year: "$publishedAt" }, month: { $month: "$publishedAt" } }, count: { $sum: 1 } } }` | `{ _id: { year, month }, count }`; utile pour les tendances temporelles. |
| `$unwind` | Crée un document intermédiaire par élément d'un tableau. | `{ $unwind: "$results" }` sur `scans`. | Un résultat de scan par document; les tableaux vides sont écartés par défaut. |
| `$lookup` | Joint une collection par égalité entre champ local et champ étranger. | `{ $lookup: { from: "assets", localField: "assetId", foreignField: "_id", as: "asset" } }` | Ajoute un tableau `asset`; c'est une jointure côté serveur, pas une référence Mongoose. |

### Opérations avancées

| Opération | Définition et but dans CyberTrack | Exemple exécutable | Résultat attendu / point oral |
|---|---|---|---|
| `$facet` | Exécute plusieurs sous-pipelines sur la même entrée; pratique pour réunir statistiques et liste prioritaire. | `db.vulnerabilities.aggregate([{ $facet: { bySeverity: [{ $group: { _id: "$severity", count: { $sum: 1 } } }], critical: [{ $match: { severity: "CRITICAL" } }, { $limit: 5 }] } }])` | Un document avec `bySeverity: [...]` et `critical: [...]`; chaque branche est indépendante. |
| `$bucket` | Classe les valeurs dans des intervalles déterminés. | `db.vulnerabilities.aggregate([{ $bucket: { groupBy: "$cvss", boundaries: [0, 4, 7, 9, 10.01], default: "hors_plage", output: { count: { $sum: 1 }, average: { $avg: "$cvss" } } } }])` | Documents `{ _id: borneBasse, count, average }`; les bornes supérieures sont exclusives. |
| `$addFields` | Ajoute ou remplace un champ calculé dans le flux. | `db.vulnerabilities.aggregate([{ $addFields: { cvssPercent: { $multiply: ["$cvss", 10] } } }, { $limit: 3 }])` | Les documents ont `cvssPercent`; aucune écriture n'est faite. |
| `$switch` | Choisit une valeur à partir de branches conditionnelles. | `db.vulnerabilities.aggregate([{ $addFields: { priority: { $switch: { branches: [{ case: { $eq: ["$severity", "CRITICAL"] }, then: 1 }, { case: { $eq: ["$severity", "HIGH"] }, then: 2 }], default: 3 } } } }, { $limit: 3 }])` | Un champ `priority`; la première branche vraie est utilisée, sinon `default`. |
| `$setWindowFields` | Calcule une valeur sur une fenêtre d'observations ordonnées sans regrouper les lignes. | `db.vulnerabilities.aggregate([{ $setWindowFields: { partitionBy: "$severity", sortBy: { cvss: -1 }, output: { runningAverage: { $avg: "$cvss", window: { documents: ["unbounded", "current"] } } } } }, { $limit: 3 }])` | Chaque vulnérabilité garde ses champs et reçoit `runningAverage`; ne confondre ni partition ni groupe. |

### Relations, références et données intégrées

Dans une référence, une collection stocke un `ObjectId` et `$lookup` récupère
le document associé. Une donnée intégrée, telle que `scans.results`, se lit
directement et peut être aplatie par `$unwind`.

| Cas pratique | Exemple exécutable | Forme attendue | À expliquer à l'oral |
|---|---|---|---|
| Joindre scans et assets | `db.scans.aggregate([{ $lookup: { from: "assets", localField: "assetId", foreignField: "_id", as: "asset" } }, { $project: { status: 1, asset: { $arrayElemAt: ["$asset", 0] } } }])` | `{ status, asset: {...} }` | `assetId` est une référence; `$lookup` produit toujours un tableau avant l'aplatissement. |
| Joindre scans et users | `db.scans.aggregate([{ $lookup: { from: "users", localField: "scannedBy", foreignField: "_id", as: "operator" } }, { $project: { status: 1, operator: { $arrayElemAt: ["$operator", 0] } } }])` | `{ status, operator: {...} }` | Seuls les champs nécessaires devraient être projetés; ne pas exposer `passwordHash`. |
| Déplier les résultats et joindre les vulnérabilités | `db.scans.aggregate([{ $unwind: "$results" }, { $lookup: { from: "vulnerabilities", localField: "results.vulnerabilityId", foreignField: "_id", as: "vulnerability" } }, { $unwind: "$vulnerability" }, { $project: { scanId: "$_id", title: "$vulnerability.title", port: "$results.port" } }])` | `{ scanId, title, port }` | `$unwind` rend chaque résultat indépendant et la jointure associe son ObjectId. |
| Joindre les tâches de remédiation | Exemple complet dans [`database/relationships.js`](../database/relationships.js). Il joint `vulnerabilityId`, `assetId`, `assignedTo` et `createdBy`. | `{ taskTitle, status, vulnerability, assetType, assigneeRole, creatorRole }` | Les références évitent de recopier les documents, mais demandent des lectures/jointures explicites. |

Les pipelines de relation complets, avec explications et projection limitée,
s'exécutent avec `database/relationships.js`.

## 3. Index et mesure des performances

### Index configurés

`database/indexes.js` crée ou vérifie, sans supprimer d'index :

| Collection | Index | Rôle |
|---|---|---|
| `vulnerabilities` | `{ cveId: 1 }`, unique | Empêcher les CVE en double et accélérer les recherches exactes. |
| `vulnerabilities` | `{ severity: 1 }` | Filtrer une sévérité. |
| `vulnerabilities` | `{ severity: 1, cvss: -1 }` | Filtrer par sévérité puis trier par score décroissant. |
| `vulnerabilities` | `{ publishedAt: -1 }` | Trier/filtrer par date de publication. |
| `vulnerabilities` | texte sur `title` et `description` | Recherche textuelle MongoDB. |
| `scans` | `{ assetId: 1 }`, `{ scannedBy: 1 }` | Filtrer les scans par asset ou opérateur. |
| `remediation_tasks` | `{ vulnerabilityId: 1, assetId: 1 }`, `{ assetId: 1 }`, `{ assignedTo: 1 }`, `{ createdBy: 1 }` | Filtrer les tâches par leurs références. |

L'index de texte rend aussi possible :

```javascript
db.vulnerabilities.find(
  { $text: { $search: "nginx vulnerability" } },
  { score: { $meta: "textScore" }, cveId: 1, title: 1 }
).sort({ score: { $meta: "textScore" } })
```

**Résultat attendu :** documents correspondants avec un score de pertinence.
Les recherches `$regex` ne sont pas automatiquement accélérées par un index
texte.

### `explain("executionStats")`

`executionStats` exécute la requête et fournit les mesures du plan réellement
choisi. Le vérificateur compare le même filtre `severity: "CRITICAL"` en
forçant explicitement un scan naturel (`$natural`) et l'index
`severity_index`. Cette comparaison pédagogique ne prétend pas reconstituer un
plan historique antérieur à l'installation des index.

Exemple `mongosh` :

```javascript
db.vulnerabilities.find({ severity: "CRITICAL" })
  .hint({ $natural: 1 })
  .explain("executionStats")

db.vulnerabilities.find({ severity: "CRITICAL" })
  .hint("severity_index")
  .explain("executionStats")
```

- `COLLSCAN` : MongoDB parcourt la collection.
- `IXSCAN` : MongoDB parcourt les clés de l'index; un `FETCH` peut ensuite
  lire les documents correspondants.
- `totalDocsExamined` : documents examinés.
- `totalKeysExamined` : clés d'index examinées.
- `nReturned` : documents renvoyés.
- `executionTimeMillis` : temps mesuré pendant cette exécution; il varie selon
  la machine et la charge.

`npm test` affiche les valeurs réelles de ces champs et vérifie que les deux
plans sont effectivement observés. Ne pas recopier une durée mesurée comme une
garantie générale.

Mesure réellement obtenue sur la base locale (MongoDB 9.0.2), pour cette
exécution :

| Plan imposé | `nReturned` | `totalDocsExamined` | `totalKeysExamined` | `executionTimeMillis` |
|---|---:|---:|---:|---:|
| `COLLSCAN` | 1 073 | 10 001 | 0 | 6 |
| `IXSCAN` (`severity_index`) | 1 073 | 1 073 | 1 073 | 1 |

Cette observation confirme que les deux plans renvoient le même nombre de
documents et que le plan indexé a examiné moins de documents sur cette
exécution. Les durées ne sont pas une référence universelle et sont remesurées
par `npm test`.

## 4. Validation `$jsonSchema`

- **Définition :** une règle de collection valide les écritures au niveau du
  serveur MongoDB.
- **Syntaxe :** `collMod` reçoit `validator: { $jsonSchema: ... }`,
  `validationLevel: "strict"` et `validationAction: "error"`.
- **CyberTrack :** exiger `cveId`, `title`, `severity`, `cvss` et `publishedAt`;
  vérifier les chaînes non vides, les niveaux connus, le CVSS de 0 à 10 et la
  date BSON.
- **Exemple de configuration utilisée :**

  ```javascript
  {
    $jsonSchema: {
      bsonType: "object",
      required: ["cveId", "title", "severity", "cvss", "publishedAt"],
      properties: {
        cveId: { bsonType: "string", minLength: 1 },
        title: { bsonType: "string", minLength: 1 },
        severity: { enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
        cvss: {
          bsonType: ["double", "int", "long", "decimal"],
          minimum: 0,
          maximum: 10
        },
        publishedAt: { bsonType: "date" }
      }
    }
  }
  ```

- **Résultat attendu :** toute insertion ou mise à jour non conforme échoue
  avec l'erreur MongoDB `121` (document invalide).
- **À expliquer à l'oral :** les validateurs s'appliquent aux écritures; ils ne
  réécrivent pas les documents historiques. Le script pré-vérifie les données,
  conserve le validateur existant, passe en mode `strict`/`error` et ne modifie
  aucun document existant.

## 5. Comparaisons à retenir

| Comparaison | Différence | Application CyberTrack |
|---|---|---|
| Documents intégrés vs références | L'intégration regroupe des données lues ensemble; une référence conserve un ObjectId vers une autre collection. | `scans.results` et `remediation_tasks.history` sont intégrés; `assetId`, `scannedBy`, `vulnerabilityId` et les utilisateurs sont référencés. |
| `COLLSCAN` vs `IXSCAN` | Le premier examine la collection; le second utilise les clés d'un index puis peut charger les documents. | Comparer les statistiques mesurées pour le filtre de sévérité. Un index n'est pas automatiquement plus rapide pour toutes les requêtes. |
| `find()` vs `aggregate()` | `find()` sélectionne/projette/trie des documents; `aggregate()` enchaîne transformations, calculs et jointures. | `find()` pour une liste de CVE; agrégation pour statistiques, tendances et jointures de scans. |
| Index simple vs composé | Un index simple porte sur un champ; un index composé ordonne plusieurs champs et suit le préfixe gauche. | `{ severity: 1, cvss: -1 }` aide le filtre par sévérité puis le tri CVSS; l'ordre des champs compte. |
| Requêtes traditionnelles vs pipelines | Les requêtes traditionnelles filtrent directement; les pipelines transforment des documents en étapes. | Utiliser le plus simple qui répond au besoin; l'agrégation n'est pas automatiquement plus performante. |

## 6. Exécuter sous Windows PowerShell

Ouvrir PowerShell à la racine du projet. Les commandes lisent le fichier
`server/.env` sans en afficher le contenu ni la valeur de `MONGODB_URI`.
Ne pas démarrer Express ou React pour ce laboratoire.

```powershell
Set-Location .\server

# Créer/vérifier les index (aucun index existant n'est supprimé).
npm run db:indexes

# Pré-vérifier puis appliquer le validateur strict.
npm run db:validation

# Exécuter les vérifications, l'essai de rejet et explain(executionStats).
npm test

# Charger l'URI depuis .env dans une variable temporaire non affichée,
# puis exécuter les exemples mongosh.
$env:MONGODB_URI = node -e "require('dotenv').config({ quiet: true }); process.stdout.write(process.env.MONGODB_URI || '')"
if (-not $env:MONGODB_URI) { throw 'MONGODB_URI absent de server/.env' }
mongosh --quiet $env:MONGODB_URI --file .\database\queries.js
mongosh --quiet $env:MONGODB_URI --file .\database\relationships.js
Remove-Item Env:\MONGODB_URI
```

Le vérificateur dépend de l'existence des index et du validateur : exécuter les
trois commandes npm dans l'ordre indiqué. En cas d'échec de connexion, vérifier
que MongoDB fonctionne et que `server/.env` définit `MONGODB_URI`, sans publier
sa valeur.

## 7. Vérification automatique et limites

`npm test` se connecte à la base ciblée et vérifie les cinq collections, le
minimum de documents, les champs/valeurs CVSS, les dates BSON, les tableaux,
les résultats intégrés, la résolution des références, les index, plusieurs
pipelines incluant `$facet`, `$bucket`, `$switch` et `$setWindowFields`, puis
teste le rejet réel d'un document invalide. Il affiche ensuite les statistiques
`executionStats` mesurées sur la base locale.

Le script ne valide pas les comptes utilisateurs, ne lit pas les valeurs de
`passwordHash` et ne supprime pas de document existant. Les performances
observées dépendent de la version MongoDB, du poste et de la charge du serveur.
