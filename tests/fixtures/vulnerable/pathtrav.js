const fs = require('fs')
function download(req, res) {
  fs.readFile('/var/uploads/' + req.query.file, (e, d) => res.send(d))
}
