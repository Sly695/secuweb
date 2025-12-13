const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');

// Route pour lister les utilisateurs - PROTÉGÉE
router.get('/', authenticate, async (req, res) => {
  const sql = 'SELECT id, username, email, role FROM users';
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des utilisateurs :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

// Route pour récupérer un utilisateur spécifique - PROTÉGÉE
router.get('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  // Vérifier que l'utilisateur ne peut voir que ses infos ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  const sql = 'SELECT id, username, email, role FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'utilisateur' });
  }
});

// Route pour supprimer un utilisateur - PROTÉGÉE
router.delete('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  // Vérifier que l'utilisateur ne peut supprimer que son compte ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  const sql = 'DELETE FROM users WHERE id = ?';
  try {
    await req.db.execute(sql, [id]);
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur' });
  }
});

// Route pour modifier un utilisateur - PROTÉGÉE
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

module.exports = router;
