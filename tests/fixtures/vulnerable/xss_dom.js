function render(userInput, req) {
  el.insertAdjacentHTML('beforeend', userInput)
  document.write(location.hash.slice(1))
  node.outerHTML = req.query.html
}
