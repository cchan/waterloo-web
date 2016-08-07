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
session = require 'express-session'

db = require 'flat-file-db'
  .sync 'users.db'
crypto = require 'crypto'
whois = require 'whois'
dns = require 'dns'

app = express()
app.use helmet()
app.use bodyParser.urlencoded {extended: false}
app.use session
  secret: secrets.session
  resave: true
  saveUninitialized: false

app.set 'view engine', 'pug'


hash = (email, pass) =>
  return crypto.pbkdf2Sync pass, email + 'gnbTSKz8XFvqSsQU5X5XQHECb6zrXzXAf8prcP8dcqy9pl3V4VRPSmoN8jV0uhy', 10000, 512, 'sha256'
    .toString 'hex'

app.post '/register', (req, res, next) =>
  if /[^a-z0-9\.]/i.test req.body.uwemail
    req.session.msg = {err: 'Invalid UW email'}
  else if req.body.uwdomain != 'uwaterloo.ca' and req.body.uwdomain != 'edu.uwaterloo.ca'
    req.session.msg = {err: 'Invalid UW email'}
  else if req.body.pass != req.body.confpass
    req.session.msg = {err: 'Passwords do not match'}
  else if req.body.pass.length < 8
    req.session.msg = {err: 'Password must be at least 8 chars'}
  else if /[^a-z0-9\.]/i.test req.body.newemail
    req.session.msg = {err: 'Invalid new email'}
  else if /[^a-z0-9]/i.test req.body.domain
    req.session.msg = {err: 'Invalid domain'}
  else if /[^a-z]/i.test(req.body.tld) or !tlds.hasOwnProperty(req.body.tld)
    req.session.msg = {err: 'Invalid TLD: supported tlds are ' + JSON.stringify Object.keys tlds}
  else
    email = req.body.uwemail + '@' + req.body.uwdomain
    
    if db.has email
      req.session.msg = {err: 'UW email already used'}
      next()
    else
      dns.resolve4 req.body.domain + '.' + req.body.tld, (err, addresses) =>
        if err
          whois.lookup req.body.domain + '.' + req.body.tld, (err, data) =>
            if err
              req.session.msg = {err: 'WHOIS lookup error'}
              next()
            else if data.includes tlds[req.body.tld]
              db.put email,
                pass: hash email, req.body.pass
                email: req.body.newemail
                domain: req.body.domain
                tld: req.body.tld
              req.session.user = email
              req.session.msg = {success: 'Successfully registered!'}
              res.redirect '/manage'
            else
              req.session.msg = {err: 'Domain unavailable (WHOIS)'}
              next()
        else
          req.session.msg = {err: 'Domain unavailable (DNS)'}
          next()
    return
  next()

app.post '/login', (req, res) =>
  if req.body.hasOwnProperty('email') and req.body.hasOwnProperty('pass')
    if req.body.email and db.has(req.body.email) and db.get(req.body.email).pass == hash(req.body.email, req.body.pass)
      req.session.user = req.body.email
      req.session.msg = {success: 'Successfully logged in!'}
      res.redirect '/manage'
    else
      req.session.msg = {err: 'Incorrect email or password'}
      res.redirect '/login'

app.post '/manage', (req, res) =>
  if req.body.logout
    req.session.destroy()
    res.redirect '/login'

app.all '/login', (req, res) =>
  if db.has req.session.user
    res.redirect '/manage'
  else
    res.render 'login', _.extend req.body, req.session.msg
    req.session.msg = {}

app.all '/register', (req, res) =>
  if db.has req.session.user
    res.redirect '/manage'
  else
    res.render 'register', _.extend req.body, {tlds: tlds}, req.session.msg
    req.session.msg = {}

app.all '/manage', (req, res) =>
  if db.has req.session.user
    res.render 'manage', req.session.msg
    req.session.msg = {}
  else
    req.session.destroy()
    res.redirect '/login'

app.all '*', (req, res) =>
  if db.has req.session.user
    res.redirect '/manage'
  else
    res.redirect '/login'

app.listen PORT, 'localhost', =>
  console.log 'Listening on localhost:' + PORT
