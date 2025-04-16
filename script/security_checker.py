import re
import argparse
import socket
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Liste des mots de passe communs
COMMON_PASSWORDS = ["password", "123456", "admin", "qwerty"]
COMPROMISED_PASSWORDS_FILE = "compromised_passwords.txt"

if not Path(COMPROMISED_PASSWORDS_FILE).is_file():
    logging.error(
        "Le fichier de mots de passe compromis est introuvable : %s",
        COMPROMISED_PASSWORDS_FILE,
    )
    exit(1)


def load_compromised_passwords(file_path):
    """Charge les mots de passe compromis depuis un fichier."""
    try:
        with open(file_path, "r") as f:
            return set(line.strip() for line in f)
    except FileNotFoundError:
        logging.error("Fichier de mots de passe compromis non trouvé : %s", file_path)
        return set()


def is_password_weak(password, compromised_passwords):
    """Vérifie si un mot de passe est faible selon certaines règles."""
    length_rule = re.compile(r"^.{8,}$")  # Au moins 8 caractères
    digit_rule = re.compile(r"\d")  # Au moins un chiffre
    upper_rule = re.compile(r"[A-Z]")  # Au moins une majuscule

    if not length_rule.match(password):
        return True, "Mot de passe trop court (moins de 8 caractères)"
    if not digit_rule.search(password):
        return True, "Aucun chiffre détecté"
    if not upper_rule.search(password):
        return True, "Aucune majuscule détectée"
    if password.lower() in COMMON_PASSWORDS:
        return True, "Mot de passe trop commun"
    if password in compromised_passwords:
        return True, "Mot de passe compromis détecté"

    return False, "Mot de passe sécurisé"


def check_passwords(file_path, compromised_passwords):
    """Vérifie les mots de passe dans un fichier et retourne ceux qui sont faibles."""
    weak_passwords = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                password = line.strip()
                is_weak, reason = is_password_weak(password, compromised_passwords)
                if is_weak:
                    weak_passwords.append((password, reason))
    except FileNotFoundError:
        logging.error("Fichier non trouvé : %s", file_path)
    return weak_passwords


def generate_report(weak_list, output_file):
    """Génère un rapport des mots de passe faibles."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:  # Ajout de encoding='utf-8'
            f.write("Rapport de Vulnérabilités:\n")
            for pwd, reason in weak_list:
                f.write(f"- {pwd} → {reason}\n")
        logging.info("Rapport généré avec succès : %s", output_file)
    except Exception as e:
        logging.error("Erreur lors de la génération du rapport : %s", e)


def check_port(host, port):
    """Vérifie si un port est ouvert sur un hôte donné."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((host, port))
            return result == 0  # Retourne True si le port est ouvert
    except Exception as e:
        logging.error(
            "Erreur lors de la vérification du port %s:%d : %s", host, port, e
        )
        return False


def send_email_report(
    sender_email,
    sender_password,
    recipient_email,
    subject,
    body,
    smtp_server="smtp.gmail.com",
    smtp_port=587,
):
    """Envoie le rapport par email."""
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        logging.info("Email envoyé avec succès à %s", recipient_email)
    except Exception as e:
        logging.error("Erreur lors de l'envoi de l'email : %s", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vérificateur de sécurité de bases de données"
    )
    parser.add_argument("input", help="Fichier des mots de passe")
    parser.add_argument("output", help="Fichier de rapport")
    parser.add_argument(
        "--email", help="Envoyer le rapport par email", action="store_true"
    )
    parser.add_argument("--sender_email", help="Email de l'expéditeur")
    parser.add_argument("--sender_password", help="Mot de passe de l'expéditeur")
    parser.add_argument("--recipient_email", help="Email du destinataire")
    args = parser.parse_args()

    # Validation des fichiers
    if not Path(args.input).is_file():
        logging.error("Le fichier d'entrée n'existe pas : %s", args.input)
        exit(1)

    if not Path(COMPROMISED_PASSWORDS_FILE).is_file():
        logging.error(
            "Le fichier de mots de passe compromis est introuvable : %s",
            COMPROMISED_PASSWORDS_FILE,
        )
        exit(1)

    compromised_passwords = load_compromised_passwords(COMPROMISED_PASSWORDS_FILE)
    weak_passwords = check_passwords(args.input, compromised_passwords)
    generate_report(weak_passwords, args.output)
    logging.info(
        "%d mots de passe faibles détectés. Rapport sauvegardé dans %s.",
        len(weak_passwords),
        args.output,
    )

    # Vérification du port MySQL
    if check_port("localhost", 3306):
        logging.warning("Attention : Port MySQL (3306) est ouvert !")

    # Envoi du rapport par email si demandé et si les informations sont complètes
    if args.email:
        if args.sender_email and args.sender_password and args.recipient_email:
            try:
                with open(
                    args.output, "r", encoding="utf-8"
                ) as f:  # Ajout de encoding='utf-8'
                    report_content = f.read()
                send_email_report(
                    sender_email=args.sender_email,
                    sender_password=args.sender_password,
                    recipient_email=args.recipient_email,
                    subject="Rapport de Vulnérabilités",
                    body=report_content,
                )
            except FileNotFoundError:
                logging.error("Fichier de rapport introuvable : %s", args.output)
        else:
            logging.error(
                "Les informations d'email sont incomplètes. Le rapport ne sera pas envoyé."
            )
