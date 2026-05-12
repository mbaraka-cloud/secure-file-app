# Secure File App

Application web full-stack permettant l’upload, le partage et le téléchargement sécurisé de fichiers.

Ce projet a été réalisé dans le cadre de ma formation en génie logiciel. Il met en pratique les bases du développement web full-stack, de l’authentification, du contrôle d’accès, de la manipulation de fichiers, des API REST et du déploiement avec Docker.

## Objectif du projet

L’objectif de Secure File App est de proposer une application web permettant à des utilisateurs de gérer et partager des fichiers de manière sécurisée.

Le projet m’a permis de travailler sur plusieurs aspects importants du développement d’application :

- conception d’une architecture web full-stack ;
- création de routes back-end ;
- gestion des formulaires ;
- authentification utilisateur ;
- contrôle d’accès ;
- manipulation de données ;
- réponses au format JSON ;
- journalisation des actions ;
- environnement Dockerisé.

## Fonctionnalités principales

- Création et authentification des utilisateurs
- Upload sécurisé de fichiers
- Partage de fichiers entre utilisateurs
- Téléchargement des fichiers
- Gestion des droits d’accès
- Journalisation des actions utilisateurs
- Routes back-end pour certaines fonctionnalités
- Utilisation de PostgreSQL pour la base de données
- Utilisation de Redis pour certains services techniques
- Déploiement local avec Docker

## Technologies utilisées

- Python
- Flask
- HTML5
- CSS3
- JavaScript ES6
- API REST
- JSON
- PostgreSQL
- Redis
- Docker
- Nginx
- Pytest

## Structure du projet

```text
secure-file-app/
├── app/
│   ├── billing/
│   ├── forms/
│   ├── models/
│   ├── routes/
│   ├── static/
│   ├── templates/
│   └── utils/
├── migrations/
├── scripts/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.py
└── config.py

## Installation locale

Cette section explique comment lancer le projet en local sur un ordinateur.

### Prérequis

Avant de lancer le projet, il faut avoir installé :

- Git
- Docker Desktop
- Un navigateur web

Le projet utilise Docker afin de faciliter le lancement de l’application avec ses services techniques, notamment PostgreSQL et Redis.

### 1. Cloner le dépôt

Ouvrir un terminal, puis exécuter la commande suivante :

```bash
git clone https://github.com/mbaraka-cloud/secure-file-app.git
```

Entrer ensuite dans le dossier du projet :

```bash
cd secure-file-app
```

### 2. Préparer les variables d’environnement

Créer un fichier `.env` à la racine du projet.

Ce fichier sert à stocker les paramètres de configuration de l’application, par exemple la clé secrète, l’environnement Flask, l’adresse de la base de données et Redis.

Exemple de contenu possible :

```env
FLASK_ENV=development
SECRET_KEY=change-me
DATABASE_URL=postgresql://user:password@db:5432/secure_file_app
REDIS_URL=redis://redis:6379/0
```

> Remarque : les valeurs doivent être adaptées selon la configuration réelle du projet et du fichier `docker-compose.yml`.

### 3. Lancer le projet avec Docker

Une fois le fichier `.env` créé, lancer l’application avec :

```bash
docker compose up --build
```

Cette commande permet de :

- construire l’image Docker de l’application ;
- lancer le serveur web ;
- lancer les services nécessaires comme PostgreSQL et Redis ;
- préparer l’environnement de développement local.

### 4. Accéder à l’application

Après le lancement, ouvrir le navigateur et accéder à l’adresse locale indiquée dans le terminal.

Selon la configuration Docker, l’application peut être accessible par exemple sur :

```text
http://localhost:5000
```

ou sur un autre port défini dans le fichier `docker-compose.yml`.

### 5. Arrêter l’application

Pour arrêter l’application, revenir dans le terminal et faire :

```bash
Ctrl + C
```

Puis, pour arrêter complètement les conteneurs Docker :

```bash
docker compose down
```

## Tests

Le projet contient un dossier de tests permettant de vérifier certaines fonctionnalités.

Pour lancer les tests localement :

```bash
pytest
```

Si le projet est lancé dans Docker, les tests peuvent aussi être exécutés à l’intérieur du conteneur selon la configuration du projet.

## Ce que j’ai appris avec ce projet

Ce projet m’a permis de renforcer mes bases en développement web full-stack.

J’ai notamment appris à :

- structurer une application web avec Flask ;
- créer des routes back-end ;
- manipuler des formulaires ;
- gérer l’authentification utilisateur ;
- mettre en place une logique de contrôle d’accès ;
- manipuler des données au format JSON ;
- utiliser PostgreSQL comme base de données ;
- utiliser Redis pour certains services techniques ;
- organiser un environnement de développement avec Docker ;
- tester, déboguer et améliorer progressivement une application.

## Améliorations prévues

Plusieurs améliorations peuvent être envisagées pour faire évoluer le projet :

- moderniser davantage l’interface utilisateur ;
- ajouter une documentation API plus détaillée ;
- ajouter davantage de tests automatisés ;
- améliorer la gestion des erreurs ;
- renforcer la sécurité des fichiers uploadés ;
- ajouter un tableau de bord utilisateur ;
- ajouter une intégration IA pour l’analyse automatique des fichiers ;
- améliorer l’expérience mobile et responsive.

## Auteur

Rivotiana Philippe Randriatsarafara  
Développeur web junior  
Portfolio : https://mbaraka-cloud.github.io/portfolio-rivotiana-philippe/  
GitHub : https://github.com/mbaraka-cloud
