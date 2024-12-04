import User from '../models/userModel.js';
import jwt from 'jsonwebtoken';

// Middleware pour protéger les routes en vérifiant le token JWT.
const protect = async (req, res, next) => {
  try {
    // Récupérer le token JWT depuis les cookies.
    const token = req.cookies.jwt;

    // Si le token est absent, retourner une erreur 401 (non autorisé).
    if (!token) {
      return res.status(401).json({ message: 'Token non fourni' });
    }

    // Vérifier et décoder le token JWT
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Si le token est invalide, retourner une erreur 401.
    if (!decodedToken) {
      return res.status(401).json({ message: 'Token invalide' });
    }

    // Chercher l'utilisateur dans la base de données en utilisant l'ID du token
    req.user = await User.findById(decodedToken.userId).select('-password');

    // Si l'utilisateur n'est pas trouvé, retourner une erreur 401.
    if (!req.user) {
      return res.status(401).json({ message: 'Utilisateur non trouvé' });
    }

    // Passer au middleware suivant
    next();
  } catch (error) {
    // En cas d'erreur, retourner une erreur 401 avec le message de l'erreur.
    res.status(401).json({ message: error.message || 'Erreur d\'authentification' });
  }
};

// Middleware pour vérifier si l'utilisateur est un administrateur.
const admin = (req, res, next) => {
  try {
    if (!req.user || !req.user.isAdmin) {
      return res.status(403).json({ message: 'Accès interdit : Vous devez être un administrateur.' });
    }
    next();
  } catch (error) {
    res.status(403).json({ message: error.message || 'Accès interdit' });
  }
};

export { protect, admin };
