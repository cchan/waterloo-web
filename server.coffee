PORT = 29532

secrets = require './secrets'

Namecheap = require 'namecheap-api'
Cloudflare = require 'cloudflare'
Mailgun = require 'mailgun-js'

helmet = require 'helmet'
express = require 'express'

app = express()
app.use helmet()

app.get '/' (req, res) =>
  res.send 'Hello'

app.use express.static 'static'

app.listen PORT, 'localhost', =>
  console.log 'Listening on localhost:#{PORT}'
