db.query("SELECT id, name FROM users WHERE id = $1", [req.params.id]);
