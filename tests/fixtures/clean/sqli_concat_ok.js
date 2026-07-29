function getUser(userId) {
  const q = "SELECT * FROM users WHERE id = $1"
  logger.info("Updated " + count + " rows from cache")
  return db.query(q, [userId])
}
