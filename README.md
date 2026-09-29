# Auth Starter

Service d’authentification Spring Boot fournissant une authentification par identifiant/mot de passe, des jetons d’accès JWT signés en RSA, la rotation des refresh tokens, la révocation à la déconnexion et une gestion sécurisée du refresh token côté navigateur via un cookie HttpOnly.

## Présentation

`auth-starter` centralise les mécanismes d’authentification tout en séparant clairement les responsabilités des deux types de jetons :

- **Access token** : retourné dans le corps de la réponse HTTP, conservé de préférence uniquement en mémoire côté client et envoyé comme Bearer token.
- **Refresh token** : persisté côté serveur et transmis au navigateur grâce à un **cookie HttpOnly**. Il n’est jamais exposé dans la réponse JSON.
- **Rotation du refresh token** : chaque refresh réussi marque le refresh token courant comme utilisé et en génère un nouveau.
- **Logout** : révoque le refresh token et supprime son cookie côté navigateur.
- **Signature JWT** : les access tokens sont signés en RSA via `JwtEncoder` et l’implémentation Nimbus de Spring Security.

## Flux d’authentification

### Connexion

```text
Client                     Auth Starter
  |                            |
  | POST /auth/login           |
  | username + password        |
  |--------------------------->|
  |                            | authentification
  |                            | création access token
  |                            | création refresh token
  |                            |
  | 200 OK                     |
  | accessToken dans le JSON   |
  | refreshToken en cookie     |
  | HttpOnly via Set-Cookie    |
  |<---------------------------|
```

### Rafraîchissement

```text
Client                     Auth Starter
  |                            |
  | POST /auth/refresh         |
  | Cookie: refreshToken=A     |
  |--------------------------->|
  |                            | validation de A
  |                            | A marqué comme utilisé
  |                            | création access token B
  |                            | création refresh token B
  |                            |
  | accessToken B dans JSON    |
  | Set-Cookie: refreshToken=B |
  |<---------------------------|
```

### Déconnexion

```text
Client                     Auth Starter
  |                            |
  | POST /auth/logout          |
  | Cookie: refreshToken       |
  |--------------------------->|
  |                            | révocation du refresh token
  |                            | expiration du cookie
  | 204 No Content             |
  |<---------------------------|
```

## API

Les exemples supposent que l’application est disponible localement à l’adresse :

```text
http://localhost:8081/authstarter
```

### `POST /auth/login`

Authentifie un utilisateur avec son identifiant et son mot de passe.

Requête :

```json
{
  "username": "admin",
  "password": "password"
}
```

Réponse en cas de succès :

```json
{
  "accessToken": "<jwt>",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

La réponse contient également le refresh token dans un cookie, par exemple :

```http
Set-Cookie: refreshToken=<token>; Path=/; HttpOnly; SameSite=Lax
```

Le refresh token ne doit jamais être retourné dans le corps JSON.

### `POST /auth/refresh`

Génère un nouvel access token à partir du refresh token contenu dans le cookie HttpOnly. Aucun corps JSON n’est nécessaire.

```http
POST /authstarter/auth/refresh
Cookie: refreshToken=<token>
```

Réponse en cas de succès :

```json
{
  "accessToken": "<nouveau-jwt>",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

Lors d’un refresh réussi, le refresh token est également renouvelé grâce à la rotation et la nouvelle valeur est renvoyée via `Set-Cookie`.

### `POST /auth/logout`

Révoque le refresh token courant et fait expirer son cookie.

Réponse attendue :

```text
204 No Content
```

## Access tokens JWT

Les access tokens contiennent notamment les claims suivants :

- `iss` : issuer configuré ;
- `sub` : nom de l’utilisateur authentifié ;
- `aud` : audience configurée ;
- `jti` : identifiant unique du token ;
- `iat` : date d’émission ;
- `exp` : date d’expiration ;
- `userId` : identifiant applicatif de l’utilisateur ;
- `authorities` : permissions distinctes et triées provenant des rôles de l’utilisateur.

Le type de token retourné au client est `Bearer`.

## Cycle de vie du refresh token

### À la connexion

1. Les identifiants sont authentifiés.
2. Un access token est généré.
3. Un refresh token est créé et persisté.
4. L’access token est retourné dans le JSON.
5. Le refresh token est envoyé dans un cookie HttpOnly.

### Lors du refresh

1. Le refresh token est lu depuis le cookie.
2. Le token est validé.
3. Le compte utilisateur est vérifié.
4. Le refresh token actuel est marqué comme utilisé.
5. Un nouvel access token est généré.
6. Un nouveau refresh token est créé.
7. Le nouveau refresh token remplace l’ancien dans le cookie.

### À la déconnexion

1. Le refresh token est lu depuis le cookie.
2. Il est révoqué côté serveur.
3. Le cookie est expiré côté navigateur.

## Sécurité

### Cookie HttpOnly pour le refresh token

Le refresh token est volontairement inaccessible au JavaScript du navigateur. Une application cliente ne doit donc jamais le stocker dans `localStorage`, `sessionStorage`, un `signal` Angular ou un autre état applicatif.

Paramètres recommandés en production :

- `HttpOnly=true` ;
- `Secure=true` ;
- une politique `SameSite` explicitement adaptée à l’architecture de déploiement ;
- un `Path` aussi restrictif que possible ;
- une durée de vie cohérente avec celle du refresh token côté serveur.

En développement local en HTTP, `Secure=false` peut être nécessaire. En production, HTTPS doit être utilisé et `Secure` activé.

### Gestion de l’access token

Pour une application web, l’access token doit de préférence rester uniquement en mémoire côté frontend. Il est envoyé aux APIs protégées via :

```http
Authorization: Bearer <access-token>
```

### Rotation du refresh token

Chaque refresh réussi invalide ou marque comme utilisé le refresh token courant avant d’en créer un nouveau. Cela évite qu’un ancien refresh token puisse être réutilisé normalement et permet de détecter plus facilement les tentatives de rejeu.

### CSRF

L’utilisation d’un cookie automatiquement envoyé par le navigateur implique de définir explicitement une stratégie CSRF avant la mise en production.

Il ne faut pas désactiver la protection CSRF uniquement pour contourner un problème de configuration navigateur. La stratégie doit être définie conjointement avec CORS, `SameSite`, HTTPS et la topologie réelle frontend/backend.

### CORS

Si le frontend et le backend utilisent des origines différentes, CORS doit être configuré explicitement et limité aux origines de confiance.

Les appels utilisant des cookies peuvent nécessiter l’activation des credentials côté backend et côté frontend.

Éviter les origines wildcard lorsque les credentials sont activés.

## Configuration Spring Security

Les endpoints d’authentification sont publics. Les autres endpoints sont refusés tant qu’ils ne sont pas explicitement autorisés.

Endpoints publics :

```text
/auth/login
/auth/refresh
/auth/logout
/swagger-ui/**
/swagger-ui.html
/api-docs/**
/v3/api-docs/**
```

L’application utilise une politique de session Spring Security stateless.

## Configuration applicative

Le service nécessite au minimum une configuration pour :

- l’issuer JWT ;
- l’audience JWT ;
- la durée de vie des access tokens ;
- la durée de vie des refresh tokens ;
- la clé publique RSA ;
- la clé privée RSA ;
- la datasource utilisée par les utilisateurs, rôles, permissions et refresh tokens.

Les clés privées, mots de passe et autres secrets ne doivent jamais être versionnés dans Git. Utiliser le mécanisme de gestion des secrets adapté à chaque environnement.

## Développement local

### Prérequis

- JDK compatible avec le projet ;
- Maven ;
- base de données configurée ;
- clés RSA et configuration applicative nécessaires.

### Compiler et tester

```bash
mvn clean verify
```

### Démarrer l’application

```bash
mvn spring-boot:run
```

Dans les exemples actuels, l’application est disponible à l’adresse :

```text
http://localhost:8081/authstarter
```

Adapter cette URL si la configuration locale diffère.

## Tests avec curl

### Login et sauvegarde du cookie

```bash
curl -i -c cookies.txt \
  -X POST \
  'http://localhost:8081/authstarter/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "password"
  }'
```

Vérifier la présence du header :

```text
Set-Cookie: refreshToken=...; Path=/; HttpOnly; SameSite=Lax
```

Le JSON doit contenir l’access token, mais aucun refresh token.

### Refresh avec rotation du cookie

```bash
curl -i \
  -b cookies.txt \
  -c cookies.txt \
  -X POST \
  'http://localhost:8081/authstarter/auth/refresh'
```

La réponse doit contenir un nouvel access token ainsi qu’un nouveau `Set-Cookie` pour le refresh token rotaté.

Pour inspecter l’échange du cookie :

```bash
curl -v \
  -b cookies.txt \
  -c cookies.txt \
  -X POST \
  'http://localhost:8081/authstarter/auth/refresh'
```

Vérifier l’envoi :

```text
> Cookie: refreshToken=...
```

et la rotation :

```text
< Set-Cookie: refreshToken=...; Path=/; HttpOnly; SameSite=Lax
```

### Logout

```bash
curl -i \
  -b cookies.txt \
  -c cookies.txt \
  -X POST \
  'http://localhost:8081/authstarter/auth/logout'
```

Statut attendu :

```text
204 No Content
```

## Intégration avec Angular

Pour une SPA Angular, le modèle recommandé est :

- conserver l’access token uniquement en mémoire, par exemple dans un `signal` ;
- ne jamais lire ni stocker le refresh token dans Angular ;
- utiliser `withCredentials: true` pour les requêtes devant transporter le cookie lorsque la topologie des origines le nécessite ;
- ajouter l’access token aux requêtes via un interceptor HTTP ;
- lorsqu’un access token expire, appeler `/auth/refresh`, stocker le nouvel access token en mémoire puis rejouer la requête initiale ;
- éviter que plusieurs réponses `401` simultanées déclenchent plusieurs rotations concurrentes du refresh token.

Exemple d’état Angular :

```typescript
private readonly accessTokenSignal = signal<string | null>(null);
readonly accessToken = this.accessTokenSignal.asReadonly();
```

Le refresh token ne doit pas exister dans l’état Angular.

## Organisation du projet

Exemple de structure :

```text
com.qbe.auth
├── config
│   └── SecurityConfig
├── controller
│   └── AuthenticationController
├── dto
│   ├── LoginRequestDto
│   ├── TokenResponseDto
│   └── AuthenticationTokensDto
├── entity
│   ├── UserEntity
│   ├── PermissionEntity
│   └── RefreshTokenEntity
├── exception
├── properties
│   └── JwtProperties
├── repository
└── service
    ├── AuthenticationService
    ├── RefreshTokenService
    └── UserService
```

`AuthenticationTokensDto` est un objet interne contenant l’access token et le refresh token. `TokenResponseDto` correspond au contrat public de l’API et ne doit jamais exposer le refresh token.

## Stratégie de tests

### Authentification

Tester au minimum :

- authentification valide avec HTTP 200 ;
- présence de l’access token, du type et de l’expiration dans le body ;
- absence du refresh token dans le body ;
- présence du refresh token dans `Set-Cookie` ;
- attributs `HttpOnly`, `Path`, `SameSite` et `Secure` en production ;
- rejet d’identifiants invalides.

### Refresh

Tester au minimum :

- refresh valide depuis le cookie ;
- génération d’un nouvel access token ;
- rotation du refresh token ;
- invalidation ou marquage comme utilisé de l’ancien refresh token ;
- émission du nouveau refresh token dans `Set-Cookie` ;
- rejet d’un token expiré, invalide, révoqué ou déjà utilisé ;
- refus du refresh lorsque l’utilisateur est désactivé.

### Logout

Tester au minimum :

- révocation du refresh token ;
- expiration du cookie ;
- impossibilité de réutiliser le token révoqué.

### JWT

Tester au minimum :

- issuer ;
- audience ;
- expiration ;
- `userId` ;
- permissions attendues ;
- absence de doublons dans les authorities.

## Documentation de l’API

Lorsque Swagger/OpenAPI est activé, les endpoints habituels sont :

```text
/swagger-ui/index.html
/v3/api-docs
```

Éviter d’exposer l’interface Swagger publiquement en production sauf décision explicite.

## Checklist avant production

Avant tout déploiement en production, vérifier :

- HTTPS obligatoire ;
- cookie refresh token avec `Secure` et `HttpOnly` ;
- politique `SameSite` adaptée au déploiement ;
- `Path` et éventuellement `Domain` du cookie volontairement limités ;
- stratégie CSRF explicitement définie ;
- CORS limité aux origines de confiance ;
- rotation des refresh tokens active ;
- détection/rejet de la réutilisation d’un ancien refresh token ;
- durée de vie finie des refresh tokens ;
- durée de vie courte des access tokens ;
- clés privées RSA et secrets hors du dépôt Git ;
- aucune donnée sensible dans les logs ;
- aucun access token ou refresh token écrit dans les logs ;
- protection contre le brute force / rate limiting étudiée sur `/auth/login` et `/auth/refresh` ;
- contraintes et index de base de données adaptés au stockage des refresh tokens.

## Dépannage

### `/auth/refresh` renvoie 403 ou aucun cookie n’est reçu

Vérifier en priorité le `Path` du cookie.

Par exemple, si l’application est déployée sous `/authstarter`, un cookie avec `Path=/auth` ne correspond pas à `/authstarter/auth/refresh`.

Pendant le développement, `Path=/` permet de simplifier le diagnostic. En production, utiliser ensuite le chemin le plus restrictif correspondant réellement aux endpoints concernés.

Commande de diagnostic :

```bash
curl -v -b cookies.txt \
  -X POST \
  'http://localhost:8081/authstarter/auth/refresh'
```

Vérifier que curl envoie :

```text
> Cookie: refreshToken=...
```

### Le serveur renvoie le cookie mais le navigateur ne le conserve pas

Vérifier :

- `Secure` par rapport à HTTP/HTTPS ;
- la politique `SameSite` ;
- `Path` et `Domain` ;
- la configuration CORS ;
- la gestion des credentials côté frontend ;
- le caractère same-site ou cross-site de l’architecture déployée.

### Le refresh fonctionne une fois puis l’ancien token est refusé

C’est le comportement attendu avec la rotation des refresh tokens. Le client doit continuer avec le nouveau cookie généré par la réponse au refresh précédent.

## Contribution

Avant de proposer une modification :

```bash
mvn clean verify
```

Toute modification du mécanisme d’authentification doit être accompagnée de tests. Ne pas affaiblir les paramètres de sécurité sans en documenter explicitement l’impact et ne jamais versionner de secrets, clés privées ou tokens réels.
