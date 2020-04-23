let express = require("express");
let storage = require("../Storage.js")
let bodyParser = require('body-parser')
let session = require("express-session")
let randomstring = require("randomstring")
let utilities = require("../Utilities.js")

////////////////
// APP CONFIG //
////////////////

let app = express();

app.use(session({
  secret: 'oauth-auth-secret',
  name: 'auth-session',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../public/AuthServer');
app.set('json spaces', 4);

app.use('/', express.static('../public/AuthServer'));

///////////////
// ENDPOINTS //
///////////////

app.get('/', function(_, res) {
	res.render('Index', {clients: storage.clients, authServer: storage.authServerEndpoints})
})

app.get('/authorize', function(req, res) {
  let request = {
    // Required
    response_type: req.query.response_type,
    client_id: req.query.client_id,

    // Optional
    redirect_uri: req.query.redirect_uri,
    scope: req.query.scope.split(" "),
    state: req.query.state
  }
  
  // Validate request required fields and redirect uri
  if(request.response_type == null || request.client_id == null || !utilities.validRedirectUri(request.client_id, request.redirect_uri, storage.clients))
    res.redirect(request.redirect_uri + "?error=invalid_request&state=" + request.state)

  // Validate <response_type> 
  if(request.response_type != "code")
    res.redirect(request.redirect_uri + "?error=unsupported_response_type&state=" + request.state)

  // Validate <client_id>
  if(!utilities.validClient(request.client_id, storage.clients))
    res.redirect(request.redirect_uri + "?error=unauthorized_client&state=" + request.state)

  // Validate <scope> 
  if(!utilities.validScope(request.scope))
    res.redirect(request.redirect_uri + "?error=invalid_scope&state=" + request.state)

  // Authenticate resource owner
  req.session.request = request
  res.redirect('/authentication')
});

app.get('/authentication', function(req, res) {    
  if(req.session.userID == req.session.request.state)
    res.redirect('/permissions')
  else
	  res.render('Auth', {status: req.query.status == null ? "" : "Invalid credentials"})
})

app.post('/authentication', function(req, res) { 
  // Check if credentials are valid or not
  let username = req.body.username

  if(storage.rsrcOwners[username] != null && utilities.computeHash(req.body.password) == storage.rsrcOwners[username]) {    
    req.session.userID = req.session.request.state           
    res.redirect('/permissions') 
  }
  else
    res.redirect("/authentication?status=auth_failed")  
})

app.get('/permissions', function(req, res) {
  // Determines whether the user is authenticated or not
  if(req.session.userID != req.session.request.state)
    res.redirect('/')
  else
    res.render('AuthDecision', {client_id: req.session.request.client_id,
                                scope: req.session.request.scope,
                                deny_uri: req.session.request.redirect_uri + "?error=access_denied&state=" + req.session.request.state
                                })
})

app.post('/permissions', function(req, res) {
  // Generate authorization code 
  let auth_code = randomstring.generate(64)

  // Generate code expiration date
  let d = new Date();
  let expiration = Math.round(d.getTime() / 1000) + 600
// TODO - Store allowed scope
  storage.authCodes[req.session.request.client_id] = {"code": auth_code, 
                                              "expiration": expiration, 
                                              "redirection_uri": req.session.request.redirect_uri,
                                              "used": false
                                            }
                                            
  // Update storage data
  require('fs').writeFileSync('AuthServer/json/AuthCodes.json', JSON.stringify(storage.authCodes, null, 2));                 
  
  res.redirect(req.session.request.redirect_uri + "?code=" + auth_code + "&state=" + req.session.request.state)
})

app.post('/token', function(req, res) {
  let credentials = new Buffer.from(req.headers.authorization.split(" ")[1], 'base64').toString('ascii').split(":")
  
  for(client of storage.clients) {
    if(client.client_id == credentials[0] && client.client_secret == credentials[1]) {
      // After succefull authentication valid token request
      if(req.body.grant_type != "authorization_code")
        return res.status(400).send({error: "unsupported_grant_type"})

      if(storage.authCodes[client.client_id] != req.body.code.client_id)
        return res.status(400).send({error: "unauthorized_client"})

      if(storage.authCodes[client.client_id].code != req.body.code || storage.authCodes[client.client_id].redirect_uri != req.body.redirect_uri)
        return res.status(400).send({error: "invalid_grant"})
                
      // HTTP Response Headers
      res.setHeader("Cache-Control", "no-store")
      res.setHeader("Pragma", "no-cache")

      return res.send({access_token: "",
                      token_type: "",
                      expires_in: "",
                      refresh_token: "",
                      scope: ""
                      })
    }               
  }

  res.status(400).send({error: "invalid_client"})
})

// Initialize server
let server = app.listen(9001, 'localhost', function () {
  console.log('OAuth Authorization Server is listening at http://localhost:%s', server.address().port)
});
 
