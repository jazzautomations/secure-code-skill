const fs = require('fs')
const path = require('path')
function readConfig() {
  return fs.readFileSync(path.join(__dirname, 'config.json'))
}
