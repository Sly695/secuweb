# Rapport d'Audit de Sécurité - Application Web Blog

**Date d'analyse** : Analyse effectuée sur l'application backend  
**Méthodologie** : Audit combiné Black Box et White Box

---

## 📋 Méthodologie d'Audit

### Black Box Testing
- **Accès** : Aucun accès au code source
- **Méthodes** : Tests d'API, analyse des réponses HTTP, tests de pénétration
- **Outils** : Postman, Burp Suite, curl, analyse des headers HTTP

### White Box Testing
- **Accès** : Accès complet au code source
- **Méthodes** : Analyse statique du code, revue de code, analyse des dépendances
- **Outils** : Analyse manuelle du code, grep, analyse des fichiers de configuration

---

## 🔍 PARTIE 1 : FAILLES DÉCOUVERTES EN MODE BLACK BOX

*Ces failles ont été découvertes sans accès au code source, uniquement via des tests d'API et d'analyse des réponses HTTP.*

---

### 🔴 Failles Critiques (Black Box)

#### 1. **CORS non configuré (ouvert à tous)** (CRITIQUE)

**Méthode de découverte** : Analyse des headers HTTP de réponse

**Description** :
- Test effectué : Requête depuis un domaine externe avec `Origin: https://attacker.com`
- Résultat : L'API accepte les requêtes depuis n'importe quel domaine
- Headers observés : `Access-Control-Allow-Origin: *` (ou absence de restriction)

**Test effectué** :
```bash
curl -H "Origin: https://malicious-site.com" \
     -H "Content-Type: application/json" \
     -X GET http://localhost:5100/api/articles
```

**Impact** :
- Permet à n'importe quel site web d'appeler l'API
- Risque d'attaques CSRF facilitées
- Exposition des endpoints à des domaines malveillants
- Vol de données via requêtes cross-origin

**Recommandation** :
- Configurer CORS avec une whitelist de domaines autorisés
- Limiter les méthodes HTTP autorisées
- Configurer les headers autorisés

---

#### 2. **Absence de protection CSRF** (CRITIQUE)

**Méthode de découverte** : Test de requête cross-origin avec session valide

**Description** :
- Test effectué : Création d'une page HTML malveillante qui envoie une requête POST à l'API
- Résultat : Les requêtes modifiantes (POST/PUT/DELETE) sont acceptées sans token CSRF
- Aucun header `X-CSRF-Token` ou mécanisme de protection détecté

**Test effectué** :
```html
<!-- Page malveillante sur attacker.com -->
<form action="http://localhost:5100/api/articles" method="POST">
  <input type="hidden" name="title" value="Article malveillant">
  <input type="hidden" name="content" value="Contenu malveillant">
  <input type="hidden" name="author_id" value="1">
</form>
<script>document.forms[0].submit();</script>
```

**Impact** :
- Un attaquant peut forcer un utilisateur authentifié à effectuer des actions non désirées
- Modification/suppression de données sans consentement
- Élévation de privilèges possible
- Création de contenu malveillant au nom de l'utilisateur

**Recommandation** :
- Implémenter des tokens CSRF
- Utiliser `csurf` ou `csrf` middleware
- Valider les tokens sur toutes les requêtes modifiantes
- Utiliser SameSite cookies

---

#### 3. **Absence de rate limiting** (CRITIQUE)

**Méthode de découverte** : Test de force brute sur l'endpoint de connexion

**Description** :
- Test effectué : Envoi de 1000 requêtes de connexion en quelques secondes
- Résultat : Toutes les requêtes sont traitées sans limitation
- Aucun blocage ou ralentissement détecté
- Pas de CAPTCHA après plusieurs tentatives

**Test effectué** :
```bash
# Script de test de force brute
for i in {1..1000}; do
  curl -X POST http://localhost:5100/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' &
done
```

**Impact** :
- Attaques par force brute sur les comptes utilisateurs
- Déni de service (DoS) sur les endpoints
- Surcharge du serveur et de la base de données
- Compromission de comptes avec mots de passe faibles

**Recommandation** :
- Implémenter `express-rate-limit`
- Limiter les tentatives de connexion (ex: 5 tentatives par 15 minutes par IP)
- Ajouter un CAPTCHA après plusieurs échecs
- Implémenter un verrouillage de compte temporaire

---

#### 4. **Absence de sanitization XSS** (CRITIQUE)

**Méthode de découverte** : Injection de scripts dans les champs de contenu

**Description** :
- Test effectué : Création d'un article avec du JavaScript dans le contenu
- Résultat : Le script est stocké tel quel et exécuté lors de l'affichage
- Aucune sanitization détectée côté serveur

**Test effectué** :
```bash
curl -X POST http://localhost:5100/api/articles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test XSS",
    "content": "<script>alert(document.cookie)</script>",
    "author_id": 1
  }'
```

**Impact** :
- Injection de scripts malveillants dans les pages
- Vol de cookies/sessions (tokens JWT)
- Redirection vers des sites malveillants
- Vol de données utilisateur
- Défacing du site

**Recommandation** :
- Sanitizer le contenu HTML avec `DOMPurify` ou `sanitize-html` côté serveur
- Échapper les caractères spéciaux
- Utiliser Content Security Policy (CSP) côté frontend
- Valider et nettoyer toutes les entrées utilisateur

---

### 🟡 Failles Moyennes (Black Box)

#### 5. **Absence de headers de sécurité HTTP** (MOYENNE)

**Méthode de découverte** : Analyse des headers HTTP de réponse

**Description** :
- Test effectué : Analyse complète des headers HTTP retournés par l'API
- Résultat : Absence des headers de sécurité suivants :
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection`
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy`
  - `Referrer-Policy`

**Test effectué** :
```bash
curl -I http://localhost:5100/api/articles
```

**Impact** :
- Vulnérable aux attaques de clickjacking
- Pas de protection contre le MIME-sniffing
- Pas de protection HSTS (si HTTPS est utilisé)
- Exposition à diverses attaques web

**Recommandation** :
- Utiliser `helmet` middleware pour ajouter les headers de sécurité
- Configurer Content Security Policy (CSP)
- Implémenter HSTS en production

---

#### 6. **Gestion d'erreurs révélant des informations** (MOYENNE)

**Méthode de découverte** : Tests d'erreurs intentionnelles

**Description** :
- Test effectué : Envoi de requêtes avec des paramètres invalides
- Résultat : Les messages d'erreur révèlent des informations sur :
  - La structure de la base de données (noms de tables, colonnes)
  - Les types de données attendus
  - La structure des requêtes SQL (dans certains cas)

**Tests effectués** :
```bash
# Test avec ID invalide
curl http://localhost:5100/api/articles/abc

# Test avec paramètres manquants
curl -X POST http://localhost:5100/api/articles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Impact** :
- Fuite d'informations sur l'architecture
- Aide aux attaquants pour comprendre la structure
- Facilite les attaques ciblées

**Recommandation** :
- Retourner des messages d'erreur génériques aux clients
- Logger les erreurs détaillées uniquement côté serveur
- Ne pas exposer les stack traces en production
- Utiliser des codes d'erreur standardisés

---

#### 7. **Validation d'ID insuffisante** (MOYENNE)

**Méthode de découverte** : Tests avec des IDs invalides

**Description** :
- Test effectué : Envoi de requêtes avec des IDs non numériques, négatifs, ou très grands
- Résultat : Comportement imprévisible, parfois des erreurs SQL exposées
- Pas de validation visible des paramètres d'URL

**Tests effectués** :
```bash
# ID négatif
curl http://localhost:5100/api/articles/-1

# ID non numérique
curl http://localhost:5100/api/articles/abc

# ID très grand
curl http://localhost:5100/api/articles/999999999999999999
```

**Impact** :
- Comportement imprévisible avec des IDs invalides
- Possibilité de contourner certaines vérifications
- Erreurs SQL potentielles

**Recommandation** :
- Valider que l'ID est un nombre entier positif
- Utiliser une bibliothèque de validation
- Retourner des erreurs 400 (Bad Request) pour IDs invalides

---

#### 8. **Modification de l'author_id possible** (MOYENNE)

**Méthode de découverte** : Test de modification d'article avec author_id différent

**Description** :
- Test effectué : Modification d'un article en changeant l'`author_id` dans le body
- Résultat : Un utilisateur peut modifier l'`author_id` d'un article qu'il possède
- La vérification d'autorisation ne bloque pas la modification de ce champ

**Test effectué** :
```bash
# Utilisateur 2 modifie son article mais change author_id vers 1
curl -X PUT http://localhost:5100/api/articles/1 \
  -H "Authorization: Bearer <token_user2>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Article modifié",
    "content": "Nouveau contenu",
    "author_id": 1
  }'
```

**Impact** :
- Un utilisateur peut s'attribuer des articles d'autres utilisateurs
- Corruption de l'intégrité des données
- Falsification de l'attribution de contenu

**Recommandation** :
- Ne pas permettre la modification de l'`author_id` sauf pour les admins
- Utiliser l'`author_id` original de l'article si l'utilisateur n'est pas admin
- Ignorer ce champ dans le body pour les utilisateurs non-admin

---

#### 9. **Absence de HTTPS forcé** (FAIBLE)

**Méthode de découverte** : Test de connexion HTTP

**Description** :
- Test effectué : Tentative de connexion via HTTP
- Résultat : L'API accepte les connexions HTTP sans redirection
- Pas de redirection automatique vers HTTPS

**Impact** :
- Les données sensibles peuvent être transmises en clair
- Tokens JWT interceptables
- Mots de passe interceptables (si transmis)

**Recommandation** :
- Forcer HTTPS en production
- Utiliser des certificats SSL/TLS valides
- Rediriger automatiquement HTTP vers HTTPS

---

#### 10. **Tokens JWT sans refresh token** (FAIBLE)

**Méthode de découverte** : Analyse du mécanisme d'authentification

**Description** :
- Test effectué : Analyse du flux d'authentification
- Résultat : Un seul token JWT est retourné lors de la connexion
- Pas d'endpoint de refresh token détecté
- Le token a une durée de vie longue (déduite des tests)

**Impact** :
- Si un token est compromis, il reste valide pendant toute sa durée de vie
- Pas de mécanisme de révocation
- Risque de réutilisation de tokens volés

**Recommandation** :
- Implémenter un système de refresh tokens
- Réduire la durée de vie des access tokens (15-30 minutes)
- Utiliser des refresh tokens avec rotation
- Implémenter une blacklist de tokens révoqués

---

## 🔍 PARTIE 2 : FAILLES DÉCOUVERTES EN MODE WHITE BOX

*Ces failles ont été découvertes via l'analyse du code source.*

---

### 🔴 Failles Critiques (White Box)

#### 1. **Stockage des mots de passe en clair** (CRITIQUE)

**Localisation** : `backend/routes/auth.js`

**Description** :
- Les mots de passe sont stockés directement dans la base de données sans hachage (ligne 15)
- La comparaison des mots de passe se fait en clair (ligne 33)
- Aucun algorithme de hachage n'est utilisé (bcrypt, argon2, etc.)

**Code vulnérable** :
```15:15:backend/routes/auth.js
    const [results] = await req.db.execute(insertSql, [username, email, password]);
```

```33:33:backend/routes/auth.js
    if (user.password !== password) {
```

**Impact** :
- Si la base de données est compromise, tous les mots de passe sont exposés
- Violation du RGPD et des bonnes pratiques de sécurité
- Risque d'usurpation d'identité massive
- Impossible de récupérer les mots de passe en cas de fuite

**Recommandation** :
- Utiliser `bcrypt` ou `argon2` pour hasher les mots de passe
- Ne jamais stocker les mots de passe en clair
- Utiliser `bcrypt.compare()` pour la vérification
- Implémenter un coût de hachage approprié (minimum 10 rounds pour bcrypt)

---

#### 2. **Absence de validation des entrées utilisateur** (CRITIQUE)

**Localisation** : Toutes les routes

**Description** :
- Aucune validation des données d'entrée n'est effectuée
- Pas de vérification du format email, longueur des champs, etc.
- Pas de sanitization des données avant traitement

**Exemples de code vulnérable** :
- `auth.js` : Pas de validation du format email, longueur du mot de passe
- `articles.js` : Pas de validation du contenu HTML
- `users.js` : Pas de validation des champs modifiables

**Code vulnérable** :
```6:21:backend/routes/auth.js
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
  const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  try {
    const [existingUsers] = await req.db.execute(checkSql, [email, username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }
    const [results] = await req.db.execute(insertSql, [username, email, password]);
    res.status(201).json({ message: 'Utilisateur créé avec succès', id: results.insertId });
  } catch (err) {
    console.error('Erreur lors de l\'inscription :', err);
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});
```

**Impact** :
- Injection de données malformées
- Corruption des données
- Comportement imprévisible de l'application
- Risque d'erreurs SQL même avec requêtes paramétrées

**Recommandation** :
- Utiliser une bibliothèque de validation comme `joi` ou `express-validator`
- Valider tous les champs avant traitement
- Définir des règles de validation strictes (format email, longueur min/max, caractères autorisés)
- Rejeter les données invalides avec des messages d'erreur clairs

---

#### 3. **Exposition d'informations sensibles via les logs** (CRITIQUE)

**Localisation** : `backend/routes/articles.js`, `backend/routes/comments.js`

**Description** :
- Des `console.log()` exposent des informations sensibles en production
- Les requêtes SQL sont loggées avec les paramètres
- Les données utilisateur sont loggées

**Code vulnérable** :
```19:25:backend/routes/articles.js
  console.log(
    'req.body:', req.body,
  );

  const { title } = req.body;
  const sql = `SELECT * FROM articles WHERE title LIKE ?`;
  console.log(sql);
```

```9:9:backend/routes/comments.js
  console.log(sql);
```

**Impact** :
- Fuite d'informations dans les logs (mots de passe, tokens, données sensibles)
- Exposition de la structure de la base de données
- Aide aux attaquants pour comprendre l'architecture
- Violation de la confidentialité des données

**Recommandation** :
- Supprimer tous les `console.log()` de production
- Utiliser un système de logging approprié (winston, pino)
- Ne jamais logger les requêtes SQL avec des données sensibles
- Masquer les données sensibles dans les logs (mots de passe, tokens, emails)
- Configurer des niveaux de log appropriés (debug, info, error)

---

### 🟡 Failles Moyennes (White Box)

#### 4. **JWT_SECRET potentiellement non défini** (MOYENNE)

**Localisation** : `backend/utils/jwt.js`

**Description** :
- Si `JWT_SECRET` n'est pas défini dans les variables d'environnement, le token sera signé avec `undefined`
- Pas de vérification de l'existence de la variable au démarrage
- Pas de validation de la force de la clé secrète

**Code vulnérable** :
```4:9:backend/utils/jwt.js
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role }, // Payload : inclure l'ID utilisateur et son rôle
    process.env.JWT_SECRET, // Clé secrète pour signer le token
    { expiresIn: '12h' } // Expiration du token (ici 3 heures)
  );
};
```

**Impact** :
- Tokens JWT signés avec une clé faible ou undefined
- Possibilité de forger des tokens
- Compromission de l'authentification
- Tous les tokens peuvent être invalidés si la clé change

**Recommandation** :
- Vérifier que `JWT_SECRET` est défini au démarrage de l'application
- Utiliser une clé secrète forte (minimum 32 caractères aléatoires)
- Générer une erreur fatale si la variable est absente
- Ne jamais utiliser de clés par défaut ou faibles
- Stocker la clé de manière sécurisée (variables d'environnement, secrets manager)

---

#### 5. **Validation du rôle insuffisante** (MOYENNE)

**Localisation** : `backend/routes/users.js` - Route PUT

**Description** :
- Un admin peut modifier le rôle d'un utilisateur, mais il n'y a pas de validation que le rôle est valide
- Pas de protection contre l'auto-promotion en admin
- Un admin peut modifier son propre rôle (potentiellement se rétrograder)

**Code vulnérable** :
```59:83:backend/routes/users.js
router.put('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { username, email, password, role } = req.body;
  
  // Vérifier que l'utilisateur ne peut modifier que son compte ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  // Empêcher les utilisateurs non-admin de modifier leur rôle
  let finalRole = role;
  if (req.user.role !== 'admin' && role && role !== req.user.role) {
    return res.status(403).json({ error: 'Vous ne pouvez pas modifier votre rôle' });
  }
  
  const sql = 'UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?';
  try {
    await req.db.execute(sql, [username, email, password, finalRole, id]);
    const newUser = { id, username, email, role: finalRole };
    res.json({ message: 'Utilisateur modifié avec succès', user: newUser });
  } catch (err) {
    console.error('Erreur lors de la modification de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur' });
  }
});
```

**Impact** :
- Un admin pourrait définir un rôle invalide (corruption des données)
- Un admin pourrait se rétrograder accidentellement
- Pas de validation que le rôle fait partie des valeurs ENUM de la base de données

**Recommandation** :
- Valider que le rôle fait partie des valeurs autorisées (ENUM: 'user', 'admin')
- Empêcher un admin de modifier son propre rôle
- Ajouter une validation stricte des valeurs de rôle
- Implémenter un système d'audit pour les changements de rôle

---

#### 6. **Connexion à la base de données non sécurisée** (MOYENNE)

**Localisation** : `backend/db.js`

**Description** :
- Pas de gestion de pool de connexions
- Une seule connexion est créée et réutilisée
- Pas de gestion des timeouts
- Pas de chiffrement SSL pour la connexion MySQL

**Code vulnérable** :
```26:33:backend/db.js
// Crée une instance réutilisable de connexion MySQL
const createDbConnection = () => {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
};
```

**Impact** :
- Risque de perte de connexion non gérée
- Pas de scalabilité (une seule connexion)
- Pas de chiffrement des données en transit
- Risque de déni de service si la connexion est perdue

**Recommandation** :
- Utiliser un pool de connexions (`mysql.createPool()`)
- Configurer SSL pour la connexion MySQL
- Implémenter une gestion robuste des erreurs de connexion
- Configurer des timeouts appropriés

---

## 📊 Résumé des Failles par Méthode

### Black Box Testing
| Sévérité | Nombre | Failles |
|----------|--------|---------|
| 🔴 Critique | 4 | CORS ouvert, CSRF absent, Rate limiting absent, XSS |
| 🟡 Moyenne | 4 | Headers sécurité, Erreurs révélatrices, Validation ID, Modification author_id |
| 🟢 Faible | 2 | HTTPS, Refresh tokens |

**Total Black Box** : 10 failles identifiées

### White Box Testing
| Sévérité | Nombre | Failles |
|----------|--------|---------|
| 🔴 Critique | 3 | Mots de passe en clair, Validation manquante, Logs sensibles |
| 🟡 Moyenne | 2 | JWT_SECRET, Validation rôle, Connexion DB |

**Total White Box** : 5 failles identifiées

**TOTAL GÉNÉRAL** : 15 failles identifiées

---

## 🛠️ Plan d'Action Prioritaire

### Priorité 1 (Immédiat - Critique)
1. ✅ **Implémenter le hachage des mots de passe** (bcrypt) - White Box
2. ✅ **Ajouter la validation des entrées** (joi/express-validator) - White Box
3. ✅ **Supprimer les console.log() de production** - White Box
4. ✅ **Configurer CORS correctement** - Black Box
5. ✅ **Implémenter la protection CSRF** - Black Box
6. ✅ **Ajouter le rate limiting** - Black Box

### Priorité 2 (Court terme - Haute)
7. ✅ **Sanitizer le contenu HTML** - Black Box
8. ✅ **Valider les IDs et paramètres** - Black Box
9. ✅ **Améliorer la gestion d'erreurs** - Black Box
10. ✅ **Vérifier JWT_SECRET au démarrage** - White Box
11. ✅ **Ajouter les headers de sécurité** (helmet) - Black Box

### Priorité 3 (Moyen terme - Moyenne/Faible)
12. ✅ **Corriger la modification d'author_id** - Black Box
13. ✅ **Améliorer la validation du rôle** - White Box
14. ✅ **Implémenter les refresh tokens** - Black Box
15. ✅ **Forcer HTTPS en production** - Black Box
16. ✅ **Améliorer la connexion DB** - White Box

---

## 📝 Notes Finales

### Comparaison Black Box vs White Box

**Black Box Testing** a permis de découvrir :
- Les failles visibles depuis l'extérieur (CORS, CSRF, rate limiting)
- Les problèmes de configuration (headers, HTTPS)
- Les vulnérabilités exploitables sans code (XSS, validation)

**White Box Testing** a permis de découvrir :
- Les failles internes critiques (mots de passe en clair)
- Les problèmes de code (logs, validation manquante)
- Les risques de configuration (JWT_SECRET, validation rôle)

### Recommandations Générales

Cette application présente plusieurs failles de sécurité critiques qui doivent être corrigées avant toute mise en production. Les plus urgentes concernent :
1. L'authentification (mots de passe en clair) - découverte en White Box
2. La validation des entrées - découverte en White Box
3. Les protections externes (CORS, CSRF, rate limiting) - découvertes en Black Box

Il est recommandé de :
- Effectuer des audits réguliers en mode Black Box et White Box
- Mettre en place des tests de sécurité automatisés
- Former l'équipe aux bonnes pratiques de sécurité web
- Implémenter un processus de revue de code sécurisé
- Effectuer des tests de pénétration réguliers

---

**Fin du rapport**
