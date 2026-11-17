# Préparation de la soutenance CyberTrack

## 30 questions techniques

### 1. Pourquoi avoir choisi ce projet ?

La gestion des vulnérabilités relie des données techniques à des décisions
opérationnelles : quelles machines sont concernées, quel risque traiter et qui
est responsable de la correction. CyberTrack permet de démontrer cette chaîne
dans une application complète, de la base MongoDB à l'interface web.

### 2. Quel problème l'application résout-elle ?

Elle centralise les vulnérabilités, actifs, résultats de scans enregistrés et
tâches de remédiation. Les filtres, les responsables, les échéances et les
statistiques rendent le suivi plus lisible qu'une collection de fichiers ou
de listes isolées.

### 3. Pourquoi MongoDB ?

Les vulnérabilités ont des listes de CWE, de produits et de références. Les
résultats d'un scan et l'historique d'une tâche sont aussi naturellement
représentés comme tableaux de sous-documents. MongoDB permet de les stocker
près de leur document propriétaire, tout en conservant des collections
séparées pour les entités réutilisées.

### 4. Pourquoi cinq collections ?

Les cinq collections reflètent les entités et les données déjà présentes :
vulnérabilités, actifs, utilisateurs, scans et tâches. Garder ce modèle évite
une migration risquée et permet de distinguer les données réutilisables des
événements ou historiques qui dépendent d'un seul parent.

### 5. Quand embarquer et quand référencer ?

J'embarque `scans.results` et `remediation_tasks.history`, car ces éléments
appartiennent à un scan ou une tâche et sont consultés avec lui. Je référence
un asset, un utilisateur ou une vulnérabilité lorsqu'ils sont partagés par
plusieurs documents et doivent conserver une identité unique.

### 6. Pourquoi conserver des ObjectId ?

Un ObjectId fournit une référence compacte et stable vers un document. Les
routes vérifient son format et l'existence de la cible avant d'accepter une
relation; les suppressions d'entités encore référencées sont refusées pour
éviter les références orphelines.

### 7. Les 10 001 vulnérabilités sont-elles des CVE officielles ?

Non. Le jeu existant contient des données de démonstration et la source
`CYBERTRACK_SIMULATED` permet de les distinguer. L'application n'affirme pas
qu'elles viennent du NVD. Un importeur officiel, avec provenance et limites de
débit, reste une évolution à construire.

### 8. À quoi sert l'index unique sur `cveId` ?

Il empêche deux documents de représenter le même identifiant CVE et accélère
les recherches d'identifiant. La contrainte est appliquée par MongoDB, donc
elle reste vraie même si deux requêtes arrivent simultanément.

### 9. Quelle différence entre COLLSCAN et IXSCAN ?

`COLLSCAN` parcourt les documents de la collection jusqu'à trouver les
correspondances. `IXSCAN` parcourt d'abord un index, puis lit les documents
associés. Sur la vérification mesurée, le filtre `severity=CRITICAL` a examiné
10 001 documents sans index et 1 073 documents avec l'index de sévérité. Ces
valeurs décrivent une exécution locale, pas une promesse générale.

### 10. Un index accélère-t-il toujours une requête ?

Non. Il occupe de l'espace et chaque insertion ou mise à jour doit aussi le
maintenir. Si une valeur correspond à la majorité de la collection, un scan
complet peut parfois coûter moins cher. Il faut vérifier le plan d'exécution et
les statistiques sur des données représentatives.

### 11. Pourquoi limiter et paginer les listes côté serveur ?

Le navigateur ne reçoit que la page demandée; le serveur ne sérialise pas les
10 000 documents dans chaque réponse. La limite maximale protège également
l'API contre des demandes de pages démesurées.

### 12. Que fait `$lookup` ?

`$lookup` joint une collection à une autre sur une clé, un peu comme une jointure
relationnelle. CyberTrack l'utilise dans les agrégations pour associer les
constats de scans aux assets et vulnérabilités sans charger toutes les
collections dans la mémoire Node.js.

### 13. À quoi sert `$unwind` ?

`$unwind` transforme chaque élément d'un tableau en document de pipeline. Pour
compter des constats individuels, le pipeline décompose `scans.results`, puis
peut grouper par asset ou vulnérabilité.

### 14. Que fait `$facet` ?

`$facet` exécute plusieurs sous-pipelines sur le même flux d'entrée. Il peut,
par exemple, produire dans une seule agrégation une distribution de sévérité
et des résultats critiques. Ce n'est pas nécessaire pour toutes les routes;
son intérêt dépend du travail partagé.

### 15. À quoi sert `$bucket` ?

`$bucket` regroupe des valeurs numériques par intervalles définis. Il permet
de créer une distribution de scores CVSS par bandes, sans déplacer tous les
scores dans l'application pour les compter.

### 16. Que calcule `$setWindowFields` ?

Cette étape calcule des résultats sur une fenêtre ordonnée de documents, par
exemple une moyenne cumulative par sévérité. Elle enrichit les documents du
pipeline sans les enregistrer dans la collection.

### 17. Comment le backend est-il organisé ?

Express monte les routes sous `/api`; les routes appliquent l'authentification
et les rôles, puis délèguent aux contrôleurs. Les modèles Mongoose décrivent
les collections; des utilitaires communs fournissent la pagination, les
validations, la sérialisation et le format d'erreur.

### 18. Pourquoi séparer `app.js` et `server.js` ?

`app.js` configure Express et est importable par les tests sans démarrer un
port. `server.js` vérifie la configuration, connecte MongoDB puis démarre
l'écoute réseau. Cette séparation rend le test d'intégration plus direct.

### 19. Comment les mots de passe sont-ils protégés ?

Ils sont hachés avec bcrypt et un coût de 12. L'API ne renvoie jamais
`passwordHash`; le changement de mot de passe repasse par le même hachage. Un
hash factice est aussi comparé lors d'un login pour réduire la différence de
temps entre compte inconnu et mot de passe incorrect.

### 20. Pourquoi un cookie JWT HttpOnly ?

Le JWT a une durée de vie limitée et est envoyé dans un cookie HttpOnly : le
JavaScript de la page ne peut pas lire le jeton. `SameSite=Strict`, la
vérification d'origine et une liste CORS réduisent les risques de requêtes
cross-site. En production, le cookie est marqué `Secure`.

### 21. Que fait le contrôle d'accès par rôle ?

Un middleware vérifie le rôle de l'utilisateur relu dans MongoDB. Les lecteurs
peuvent consulter les données, les analystes et admins gèrent les ressources,
et les routes utilisateurs sont réservées aux admins. Les comptes historiques
`ANALYST` sont reconnus comme analystes.

### 22. Comment éviter l'injection NoSQL ?

Les contrôleurs construisent eux-mêmes les filtres à partir de paramètres
validés; l'utilisateur ne fournit pas de fragment MongoDB. Un middleware
rejette les clés d'opérateur et les clés spéciales, les champs de corps sont
sur liste blanche et les recherches regex échappent les métacaractères.

### 23. Quelle est la responsabilité de Mongoose ?

Mongoose valide les types et règles du modèle, convertit les entrées et définit
les références. La validation MongoDB de la collection fournit une seconde
barrière côté base. Les contrôles applicatifs complémentaires vérifient les
ObjectId référencés.

### 24. Comment l'historique de remédiation reste-t-il fiable ?

Le client ne peut pas fournir `history`, `createdBy` ou `completedAt`. Le
serveur ajoute l'événement de création et les modifications, attribue le
créateur à l'utilisateur connecté et maintient la date de complétion lors des
changements de statut.

### 25. Que fait le frontend React ?

Le tableau de bord et les pages de ressources consomment les réponses réelles
de l'API avec cookies inclus. Les listes sont paginées; les recherches sont
temporisées côté client, puis filtrées côté serveur. Les formulaires et
confirmations d'effacement s'appuient sur les mêmes routes REST.

### 26. Les scans exécutent-ils des sondes réseau ?

Non. L'application affiche et enregistre des données de scan/import; aucune
sonde réseau n'est implémentée. Cette limite est signalée dans l'interface et
la documentation afin de ne pas présenter un enregistrement comme une analyse
réelle.

### 27. Pourquoi Docker Compose ?

Compose décrit les services MongoDB, API et interface, leurs ports, le volume
persistant et les dépendances de santé. Il facilite une démonstration locale
reproductible. Les secrets restent fournis par l'environnement et ne sont pas
inscrits dans le fichier Compose.

### 28. Que vérifie la CI ?

GitHub Actions installe les dépendances Node 24, prépare un service MongoDB de
test, exécute les tests API, Oxlint, le build Vite, les audits npm et la
construction des images. Aucun déploiement n'est déclenché.

### 29. Comment les tests évitent-ils de toucher les données métier ?

La suite prend un instantané de la base configurée, puis crée une base de test
au nom aléatoire. Les fixtures et appels HTTP ciblent cette base; le nettoyage
ne supprime que cette base temporaire et un instantané final vérifie que la
base d'origine n'a pas changé.

### 30. Quelles sont les prochaines améliorations prioritaires ?

Remplacer les champs ObjectId libres par des sélecteurs; ajouter des tests de
composants et de navigateur; auditer le déploiement avec une vraie
configuration; puis seulement développer une synchronisation CVE NVD. Les
fiches de vulnérabilité et d'asset affichent déjà les relations enregistrées.

## Cinq questions pratiques difficiles

### 1. Un administrateur supprime une vulnérabilité déjà liée à une tâche. Que se passe-t-il ?

La suppression est refusée avec `409 Conflict` si un scan ou une tâche la
référence. L'utilisateur doit d'abord traiter explicitement cette relation.
Une suppression en cascade silencieuse risquerait de détruire le contexte
d'audit ou de rendre une tâche inexploitable.

### 2. Un CVE critique est créé avec un score CVSS de 3.0. Comment réagir ?

Le modèle vérifie que le score est dans `[0,10]`, mais ne prouve pas que le
niveau textuel correspond à la version et au vecteur CVSS. Il faut valider la
cohérence métier, décider si le niveau est calculé ou importé, et conserver la
provenance. Une valeur incohérente ne doit pas être présentée comme une mesure
officielle.

### 3. La liste ralentit alors que l'API renvoie seulement 20 lignes. Où chercher ?

Je regarde d'abord `explain("executionStats")`, le filtre et le tri, puis
`totalDocsExamined`, `totalKeysExamined`, le plan et la latence. La requête de
comptage de pagination peut coûter plus cher que la page; un tri non couvert
peut aussi demander un tri mémoire. J'ajuste ensuite les index après mesure.

### 4. Le JWT d'un utilisateur est encore valide après sa désactivation. Pourquoi l'accès cesse-t-il ?

Le jeton contient une identité et un rôle signés, mais le middleware relit
l'utilisateur dans MongoDB à chaque requête et vérifie `isActive`. Il ne se fie
donc pas uniquement au rôle inscrit dans un jeton qui pourrait dater d'avant
la désactivation.

### 5. Comment ajouter un import NVD sans écraser des données locales ?

Créer un job explicite utilisant l'API officielle, respecter ses limites,
valider la réponse, identifier les documents par `cveId`, enregistrer source
et date de synchronisation, puis effectuer des upserts idempotents. Tester les
cas incomplets et les conflits dans une base isolée; ne pas relancer le seed
simulé ni écraser les champs internes sans règle de provenance.

## Script de présentation — 5 minutes

Bonjour, je vous présente CyberTrack, une plateforme de gestion et de suivi
des vulnérabilités. Le problème abordé est concret : une organisation doit
relier les avis de sécurité aux machines concernées, prioriser les corrections
et savoir qui en est responsable.

L'application repose sur cinq collections MongoDB conservées : vulnérabilités,
assets, utilisateurs, scans et tâches de remédiation. Les résultats d'un scan
et l'historique d'une tâche sont intégrés dans leur document parent, car ils
ont un cycle de vie lié. Les entités réutilisables sont référencées par
ObjectId. Cette conception garde les lectures opérationnelles simples tout en
évitant de dupliquer les utilisateurs et actifs.

Le backend est une API Express organisée en routes, middleware, contrôleurs et
modèles Mongoose. Il offre pagination, filtres, recherche, validation, rôles
et agrégations MongoDB. Les mots de passe sont hachés avec bcrypt; le JWT est
dans un cookie HttpOnly de courte durée. Les vues de statistiques sont
calculées dans MongoDB pour ne pas charger la collection entière dans Node.js.

Le frontend React fournit un tableau de bord et des pages de gestion en
français. Les données affichées viennent de l'API; les listes sont paginées et
les modifications nécessitent un rôle autorisé. Les scans correspondent à des
résultats enregistrés ou importés : CyberTrack n'exécute pas de scan réseau.
Les données simulées sont identifiées et ne sont pas présentées comme des CVE
officielles.

La suite d'intégration utilise une base temporaire nommée aléatoirement et
vérifie que la base initiale reste identique. Lors de la validation, les tests
API, le lint et le build frontend ont réussi. La vérification MongoDB a trouvé
10 001 vulnérabilités et comparé des plans réels : le scan complet a examiné
10 001 documents, alors que l'index de sévérité en a examiné 1 073 dans le cas
mesuré.

Enfin, le projet a des limites assumées : pas encore d'import NVD ni de moteur
de scan réel. Les vues de relations sont disponibles sur les fiches
vulnérabilité et asset; la sélection d'identifiants, les tests navigateur,
l'import officiel et la préparation d'un déploiement réellement configuré
restent des évolutions.
Merci.

## Trame de présentation — 10 minutes

1. **Contexte et besoin (1 min)** — centraliser les constats et transformer un
   score technique en action assignée.
2. **Périmètre et utilisateurs (1 min)** — admins, analystes, lecteurs; préciser
   que les scans sont importés/enregistrés, et non exécutés par l'application.
3. **Modèle de données (2 min)** — présenter les cinq collections, les tableaux
   embarqués, les références ObjectId et la protection contre les références
   orphelines.
4. **API et sécurité (2 min)** — routes/controllers, validation, pagination,
   bcrypt, cookie JWT, rôles, filtres sûrs et erreurs normalisées.
5. **Interface (1 min)** — connexion, tableau de bord, listes filtrées,
   formulaires, détails et responsive.
6. **Performance (1 min)** — expliquer index, COLLSCAN/IXSCAN et les mesures
   observées sans les généraliser.
7. **Qualité et livraison (1 min)** — tests sur base temporaire, CI, Docker et
   maintien du workflow MongoDB local.
8. **Limites et conclusion (1 min)** — données simulées, import NVD et scans
   réels absents; proposer une évolution sûre et mesurable.

Pendant la démonstration, privilégier un compte de test, montrer une tâche
créée puis son changement de statut, et ne jamais afficher `.env` ou un secret.
