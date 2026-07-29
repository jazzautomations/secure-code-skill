function getUser(userId) {
  const q = "SELECT * FROM users WHERE id = " + userId
  return db.query(q)
}
