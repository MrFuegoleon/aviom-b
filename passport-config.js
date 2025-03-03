const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
// Importe tes méthodes pour accéder à la base de données (ex: via MariaDB)
const { findUserByUsername } = require("./db"); // Exemple d'une fonction de recherche


passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await findUserByUsername(username); // 
      if (!user) {
        return done(null, false, { message: 'Utilisateur non trouvé' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: 'Mot de passe incorrect' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

/*
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await findUserByUsername(username);
      if (!user) {
        return done(null, false, { message: "Utilisateur non trouvé" });
      }
      // Comparaison en clair pour la simulation
      if (user.password !== password) {
        return done(null, false, { message: "Mot de passe incorrect" });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);
*/
module.exports = passport;
