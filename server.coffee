PORT = 29532

tlds =
  me: 'NOT FOUND'

secrets = require './secrets'

_ = require 'underscore'

Namecheap = require 'namecheap-api'
Cloudflare = require 'cloudflare'
Mailgun = require 'mailgun-js'

bodyParser = require 'body-parser'
helmet = require 'helmet'
express = require 'express'

db = require 'flat-file-db'
  .sync 'users.db'
crypto = require 'crypto'
whois = require 'whois'
dns = require 'dns'

app = express()
app.use helmet()
app.use bodyParser.urlencoded {extended: false}

app.set 'view engine', 'pug'


hash = (email, pass) =>
  return crypto.pbkdf2Sync pass, email + 'gnbTSKz8XFvqSsQU5X5XQHECb6zrXzXAf8prcP8dcqy9pl3V4VRPSmoN8jV0uhy', 10000, 512, 'sha512'
    .toString 'hex'

app.get '/', (req, res) =>
  res.render 'index', {tlds: tlds}
app.post '/', (req, res, next) =>
  if /[^a-z0-9\.]/i.test req.body.uwemail
    return next 'Invalid UW email'
  if req.body.uwdomain != 'uwaterloo.ca' and req.body.uwdomain != 'edu.uwaterloo.ca'
    return next 'Invalid UW email'
  if req.body.pass != req.body.confpass
    return next 'Passwords do not match'
  if req.body.pass.length < 8
    return next 'Password must be at least 8 chars'
  if /[^a-z0-9\.]/i.test req.body.newemail
    return next 'Invalid new email'
  if /[^a-z0-9]/i.test req.body.domain
    return next 'Invalid domain'
  if /[^a-z]/i.test req.body.tld or !tlds.hasOwnProperty req.body.tld
    return next 'Invalid TLD: supported tlds are ' + JSON.stringify Object.keys tlds
  
  email = req.body.uwemail + '@' + req.body.uwdomain
  
  if db.has email
    return next 'UW email already used'
  
  dns.resolve4 req.body.domain + '.' + req.body.tld, (err, addresses) =>
    if err
      whois.lookup req.body.domain + '.' + req.body.tld, (err, data) =>
        if err
          next 'WHOIS lookup error'
        else if data.includes tlds[req.body.tld]
          db.put email,
            pass: hash email, req.body.pass
            email: req.body.newemail
            domain: req.body.domain
            tld: req.body.tld
          res.contentType 'text/plain'
          res.send JSON.stringify email, null, '\t'
        else
          next 'Domain unavailable (WHOIS)'
    else
      next 'Domain unavailable (DNS)'

app.use (err, req, res, next) =>
  if typeof err == 'string'
    res.render 'index', _.extend req.body, {tlds: tlds, err: err}

app.listen PORT, 'localhost', =>
  console.log 'Listening on localhost:' + PORT
