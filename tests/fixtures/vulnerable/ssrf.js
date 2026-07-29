async function proxy(req) {
  const r = await fetch(req.query.url)
  return r.text()
}
