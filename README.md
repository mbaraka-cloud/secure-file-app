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
