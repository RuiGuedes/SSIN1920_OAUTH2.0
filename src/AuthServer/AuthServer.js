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

////////////
// GLOBAL //
////////////

let GENERATOR_SIZE = 64

///////////////
// ENDPOINTS //
///////////////

app.get('/', function(_, res) {
	res.render('Index', {clients: storage.clients, authServer: storage.authServerEndpoints})
})

/**
 * Validation of the authorization request. If the request is
 * valid it moves on to the resource owner authentication. Otherwise,
 * it redirects the client to its respective redirection uri.
 */
app.get('/authorize', function(req, res) {  
  // Validate request required fields and redirect uri
  if(req.query.response_type == null || req.query.client_id == null || !utilities.validRedirectUri(req.query.client_id, req.query.redirect_uri, storage.clients))
    return res.redirect(req.query.redirect_uri + "?error=invalid_request&state=" + req.query.state)

  // Validate response_type
  if(req.query.response_type != "code")
    return res.redirect(req.query.redirect_uri + "?error=unsupported_response_type&state=" + req.query.state)

  // Validate client_id
  if(!utilities.validClient(req.query.client_id, storage.clients))
    return res.redirect(req.query.redirect_uri + "?error=unauthorized_client&state=" + req.query.state)

  // Validate scope 
  if(!utilities.validScope(req.query.scope.split(" ")))
    return res.redirect(req.query.redirect_uri + "?error=invalid_scope&state=" + req.query.state)

  // Authenticate resource owner
  req.session.request = req.query
  res.redirect('/authentication')
});

/**
 * Determination of whether the resource owner is authenticated or not, and 
 * if not, it redirects the client to the resource owner authentication 
 * form. Otherwise it skips the authentication phase and moves on to the 
 * permissions grant phase.
 */
app.get('/authentication', function(req, res) {      
  if(req.session.userID != null && req.session.userID.includes(req.session.request.state))
    res.redirect('/permissions')
  else
	  res.render('Auth', {status: req.query.status == null ? "" : "Invalid credentials"})
})

/**
 * Validation of the resource owner credentials. If the credentials are
 * valid, the resource owner is authenticated and moves on to the 
 * permissions grant phase. Otherwise the authentication fails.
 */
app.post('/authentication', function(req, res) { 
  if(storage.rsrcOwners[req.body.username] != null && utilities.computeHash(req.body.password) == storage.rsrcOwners[req.body.username]) {    
    req.session.userID = req.body.username + "." + req.session.request.state 
    res.redirect('/permissions') 
  }
  else
    res.redirect("/authentication?status=auth_failed")  
})

/**
 * Loads the permissions grant page, only if the resource owner had 
 * authenticated successfully.
 */
app.get('/permissions', function(req, res) {
  // Determines whether the user is authenticated or not  
  if(req.session.userID == null || !req.session.userID.includes(req.session.request.state))
    res.redirect('/')
  else
    res.render('AuthDecision', {client_id: req.session.request.client_id,
                                scope: req.session.request.scope.split(" "),
                                deny_uri: req.session.request.redirect_uri + "?error=access_denied&state=" + req.session.request.state
                                })
})

/**
 * Determine whether the user is authenticated or not. If it is, then
 * it generates a new authorization code coupled with the client 
 * information, and then after storing it locally, it sends back the 
 * response to the respective client. Othewise, redirects to default 
 * authorization server endpoint.
 */
app.post('/permissions', function(req, res) {
  // Determines whether the user is authenticated or not
  if(req.session.userID == null || !req.session.userID.includes(req.session.request.state))
    return res.redirect('/')

  // Generate authorization code 
  let auth_code = randomstring.generate(GENERATOR_SIZE)
  
  // Generate code expiration date
  let d = new Date();
  let expiration = Math.round(d.getTime() / 1000) + 600
  
  storage.authCodes[auth_code] = {"client_id": req.session.request.client_id, 
                                  "expiration": expiration, 
                                  "redirect_uri": req.session.request.redirect_uri,
                                  "scope": req.body.permission,
                                  "used": false
                                }
                                            
  // Update storage data
  require('fs').writeFileSync('AuthServer/json/AuthCodes.json', JSON.stringify(storage.authCodes, null, 2));                 
  
  res.redirect(req.session.request.redirect_uri + "?code=" + auth_code + "&state=" + req.session.request.state)
})

app.post('/token', function(req, res) {
  ////////////////////////////////////////////////////
  // TODO - Clean auth_codes expired or with "used" equal to true and for each one of this codes it revokes the issued tokens
  ////////////////////////////////////////////////////
  
  let credentials = new Buffer.from(req.headers.authorization.split(" ")[1], 'base64').toString('ascii').split(":")

  for(client of storage.clients) {
    if(client.client_id == credentials[0] && client.client_secret == credentials[1]) {
      // After succefull authentication valid token request
      if(req.body.grant_type != "authorization_code")
        return res.status(400).send({error: "unsupported_grant_type", state: req.session.request.state})

      if(storage.authCodes[req.body.code] == null || storage.authCodes[req.body.code].redirect_uri != req.body.redirect_uri)
        return res.status(400).send({error: "invalid_grant", state: req.session.request.state})

      if(storage.authCodes[req.body.code].client_id != req.body.client_id)
        return res.status(400).send({error: "unauthorized_client", state: req.session.request.state})
      
      ////////////////////////////////////////////////////
      // TODO - Update "used" field to be equal to true
      ////////////////////////////////////////////////////
      
      // HTTP Response Headers
      res.setHeader("Cache-Control", "no-store")
      res.setHeader("Pragma", "no-cache")

      // Generate access token with expiration date
      let token = randomstring.generate(GENERATOR_SIZE)
      let d = new Date();
      let expiration = Math.round(d.getTime() / 1000) + 600

      storage.accessTokens[token] = {"token_type": "bearer", 
                                     "expires_in": expiration, 
                                     "refresh_token": randomstring.generate(GENERATOR_SIZE),
                                     "scope": storage.authCodes[req.body.code].scope
                                    }
                                                
      // Update storage data
      require('fs').writeFileSync('AuthServer/json/AccessTokens.json', JSON.stringify(storage.accessTokens, null, 2));

      return res.send({access_token: token,
                      token_type: storage.accessTokens[token].token_type,
                      expires_in: storage.accessTokens[token].expires_in,
                      refresh_token: storage.accessTokens[token].refresh_token,
                      scope: storage.accessTokens[token].scope
                      })
    }               
  }

  res.status(400).send({error: "invalid_client"})
})

// Initialize server
let server = app.listen(9001, 'localhost', function () {
  console.log('OAuth Authorization Server is listening at http://localhost:%s', server.address().port)
});
 
