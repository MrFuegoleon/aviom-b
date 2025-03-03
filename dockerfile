# Utilisation de l'image Node.js officielle version 18
FROM node:18

# Définir un répertoire de travail 
WORKDIR /app

# Copier uniquement les fichiers de dépendances pour optimiser le cache
COPY package.json package-lock.json ./

# Installer les dépendances
RUN npm install

# Copier tout le code source dans le conteneur
COPY . .

# Exposer le port sur lequel l'application écoute (5000)
EXPOSE 5000

# Démarrer le serveur (en mode développement)
CMD ["npm", "run", "dev"]
