ce projet consiste à rediger des programmes d'extraction et de decryptage des identifiants de differents navigateurs.
ceux developpés dans le cas d'espece sont chrome et Fire foxe
Chrome:
recuperation des identifiants dans la base de données sqllite login data ( lors de la connection, faudra
s'assurer que le navigateur chrome soit fermer sinon la connexion à la base de données pourra ne pas s'etablir)
1.	Extraction de la clé depuis le fichier Local State, encodée en Base64.
2.	Décryptage de la clé avec DPAPI pour obtenir la clé AES-256.
3.	Extraction de la version (3 octets), de l’IV (12 octets), des données chiffrées et du Tag (16 octets).
4.	Initialisation du chiffreur AES-GCM avec la clé et l’IV.
5.	Déchiffrement des données avec vérification du Tag d’authenticité.
6.	Récupération des identifiants en clair.
firefox:
1. Extraction Sel Global(item1) et structure item2 ASN1 DER",
    "2. Validation Master Password(password-check)",
    "3. Génération clé dérivée (PBKDF2-HMAC-SHA256)",
    "4. Extraction et Déchiffrement clé primaire (AES-256/CBC/PKCS5Padding)(IV complété à 16 octets)",
    "5. Décodage des données (Base64 → ASN1 DER)",
    "6. Extraction de l'IV (8 octets) des données chiffrées",
    "7. Déchiffrement des données (3DES)",
    "8. Extraction et utilisation des identifiants déchiffrés"

