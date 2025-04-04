# Vérificateur de Sécurité de Mots de Passe

Ce script vérifie la sécurité des mots de passe dans un fichier et génère un rapport des mots de passe faibles. Il inclut également des fonctionnalités avancées comme la vérification des ports ouverts et l'envoi de rapports par email.

## Fonctionnalités

- Vérification de la force des mots de passe basée sur des règles de complexité.
- Vérification contre une liste de mots de passe communs et compromis.
- Génération d'un rapport des mots de passe faibles.
- Vérification des ports ouverts sur un hôte.
- Option d'envoi du rapport par email.

## Prérequis

- Python 3.x
- Accès Internet pour l'envoi d'emails (si cette fonctionnalité est utilisée).

## Installation

1. Clonez ce dépôt ou téléchargez les fichiers.
2. Assurez-vous d'avoir Python 3.x installé sur votre machine.

## Utilisation
```bash
python security_checker.py <input_file> <output_file> [--email] [--sender_email <email>] [--sender_password <password>] [--recipient_email <email>]
```

- <input_file> : Chemin vers le fichier contenant les mots de passe à vérifier.
- <output_file> : Chemin vers le fichier où le rapport sera sauvegardé.
- email : Optionnel. Si spécifié, le rapport sera envoyé par email.
- sender_email : Email de l'expéditeur (requis si --email est spécifié).
- sender_password : Mot de passe de l'expéditeur (requis si --email est spécifié).
- recipient_email : Email du destinataire (requis si --email est spécifié).

## Exemple
```bash
python security_checker.py passwords.txt report.txt --email --sender_email user@example.com --sender_password mypassword --recipient_email recipient@example.com
```

## Fichier des Mots de Passe Compromis
Le script utilise un fichier compromised_passwords.txt pour vérifier les mots de passe contre une liste de mots de passe compromis. Assurez-vous que ce fichier est présent dans le même répertoire que le script.

## Auteur
FrancKINANI 
