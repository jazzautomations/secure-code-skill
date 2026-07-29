async function health() {
  const r = await fetch('https://api.internal.example.com/health')
  return r.ok
}
