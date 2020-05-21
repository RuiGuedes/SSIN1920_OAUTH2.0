let express = require("express")
let storage = require("../Storage.js")
let bodyParser = require('body-parser')
let session = require("express-session")
let randomstring = require("randomstring")
let utilities = require("../Utilities.js")

////////////////
// APP CONFIG //
////////////////

let app = express()

app.use(session({
  secret: 'oauth-auth-secret',
  name: 'auth-session',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug')
app.set('views', '../public/AuthServer')
app.set('json spaces', 4)

app.use('/', express.static('../public/AuthServer'))

////////////
// GLOBAL //
////////////

let SERVER = 'Auth'
let GENERATOR_SIZE = 256

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function(_, res) {
	res.render('Index', {clients: storage.clients, authServer: storage.authServerEndpoints, logs: storage.authLogs})
})

/**
 * Validation of the authorization request. If the request is
 * valid it moves on to the resource owner authentication. Otherwise,
 * it redirects the client to its respective redirection uri.
 */
app.get('/authorize', function(req, res) {  
  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/authorize :: Received the following request :: " + JSON.stringify(req.query))
  
  // Validate request required fields and redirect uri
  if(req.query.response_type == null || req.query.client_id == null || !utilities.validRedirectUri(req.query.client_id, req.query.redirect_uri, storage.clients)) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authorize :: Detected an invalid request. Redirecting the client to the specified redirection uri")
    return res.redirect(req.query.redirect_uri + "?error=invalid_request&state=" + req.query.state)
  }
  else
    utilities.updateLogs(SERVER, "/authorize :: Validated required fields presence in the request")  

  // Validate response_type
  if(req.query.response_type != "code") {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authorize :: Detected unsupported response type. Redirecting the client to the specified redirection uri")
    return res.redirect(req.query.redirect_uri + "?error=unsupported_response_type&state=" + req.query.state)
  }
  else
    utilities.updateLogs(SERVER, "/authorize :: Validated response type for authorization code grantt")  

  // Validate client_id
  if(!utilities.validClient(req.query.client_id, storage.clients)) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authorize :: Detected an invalid client identifier. Redirecting the client to the specified redirection uri")
    return res.redirect(req.query.redirect_uri + "?error=unauthorized_client&state=" + req.query.state)
  }
  else 
    utilities.updateLogs(SERVER, "/authorize :: Validated client identifier authenticity")  

  // Validate scope 
  if(!utilities.validScope(req.query.scope.split(" "))) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authorize :: Detected invalid scope. Redirecting the client to the specified redirection uri")
    return res.redirect(req.query.redirect_uri + "?error=invalid_scope&state=" + req.query.state)
  }
  else
    utilities.updateLogs(SERVER, "/authorize :: Validated scope")  

  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/authorize :: Redirecting to the resource owner authentication page")

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
  if(req.session.userID != null && req.session.userID.includes(req.session.request.state)) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authentication :: Resource owner already authenticated. Redirecting to the permissions page")
    res.redirect('/permissions')
  }
  else {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authentication :: Loading authentication page")
    res.render('Auth', {status: req.query.status == null ? "" : "Invalid credentials",
                        logs: storage.authLogs
                        })
  }
})

/**
 * Validation of the resource owner credentials. If the credentials are
 * valid, the resource owner is authenticated and moves on to the 
 * permissions grant phase. Otherwise the authentication fails.
 */
app.post('/authentication', function(req, res) { 
  if(storage.rsrcOwners[req.body.username] != null && utilities.PBKDF2(req.body.password, storage.rsrcOwners[req.body.username].salt) == storage.rsrcOwners[req.body.username].password) { 
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authentication :: Resource owner authentication succeeded. Redirecting to the permissions page")   
    req.session.userID = req.body.username + "." + req.session.request.state 
    res.redirect('/permissions') 
  }
  else {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/authentication :: Resource owner authentication failed. Redirecting to the permissions page")
    res.redirect("/authentication?status=auth_failed")  
  }
})

/**
 * Loads the permissions grant page, only if the resource owner had 
 * authenticated successfully.
 */
app.get('/permissions', function(req, res) {
  // Determines whether the user is authenticated or not  
  if(req.session.userID == null || !req.session.userID.includes(req.session.request.state)) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/permissions :: Permission denied: resource owner not authenticated. Redirecting to default endpoint")    
    res.redirect('/')
  }
  else {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/permissions :: Loading permissions page")   
    res.render('AuthDecision', {client_id: req.session.request.client_id,
                                scope: req.session.request.scope.split(" "),
                                logs: storage.authLogs,
                                deny_uri: req.session.request.redirect_uri + "?error=access_denied&state=" + req.session.request.state
                                })
  }
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
  if(req.session.userID == null || !req.session.userID.includes(req.session.request.state)) {
    // Update authorization server console logs
    utilities.updateLogs(SERVER, "/permissions :: Permission denied: resource owner not authenticated. Redirecting to default endpoint")    
    return res.redirect('/')
  }

  // Update client console logs
  utilities.updateLogs(SERVER, "/permissions :: [Post][Request] :: " + JSON.stringify(req.body))

  // Generate authorization code 
  let auth_code = randomstring.generate(GENERATOR_SIZE)
  
  // Avoid duplicated codes
  while(storage.authCodes[auth_code] != null) {
    auth_code = randomstring.generate(GENERATOR_SIZE)
  }

  // Generate code expiration date
  let d = new Date();
  let expiration = Math.round(d.getTime() / 1000) + 600
  
  // Revoke previous authorization codes and associated tokens
  utilities.revokeAuthCode(req.session.request.client_id)  
  utilities.updateLogs(SERVER, "/permissions :: Revoke previous authorization codes and associated tokens")    
  
  storage.authCodes[auth_code] = {"client_id": req.session.request.client_id, 
                                  "expiration": expiration, 
                                  "redirect_uri": req.session.request.redirect_uri,
                                  "scope": req.body.permission,
                                  "username": req.session.userID.split('.')[0],
                                  "used": false
                                }
                                            
  // Update storage data
  storage.updateAuthCodes()

  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/permissions :: Generated new authorization code :: " + JSON.stringify(storage.authCodes[auth_code]))
  utilities.updateLogs(SERVER, "/permissions :: Redirecting the resource owner to the specified redirection uri")    
  
  res.redirect(req.session.request.redirect_uri + "?code=" + auth_code + "&state=" + req.session.request.state)
})

/**
 * Token endpoint responsible for generating a new access token. The access
 * token genaration can be done through with the authorization code or with
 * the refresh token associated. For both methods the respective request must
 * be properly validated. The validation is made according the specification
 * in RFC 6749.
 */
app.post('/token', function(req, res) {
  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/token :: [Post][Request] :: " + JSON.stringify(req.body))

  let credentials = new Buffer.from(req.headers.authorization.split(" ")[1], 'base64').toString('ascii').split(":")
  
  for(client of storage.clients) {    
    // Validate client authentication
    if(credentials[0] == client.client_id && utilities.PBKDF2(credentials[1], client.salt) == client.client_secret) {  
      // Update authorization server console logs
      utilities.updateLogs(SERVER, "/token :: Client authenticated successfully")
      
      // Validate request grant_type      
      if(req.body.grant_type != "authorization_code" && req.body.grant_type != "refresh_token") {
        // Update authorization server console logs
        utilities.updateLogs(SERVER, "/token :: Detected unsupported grant type. Returning error response")
        return res.status(400).send({error: "unsupported_grant_type", state: req.body.state})
      }        
      else        
        utilities.updateLogs(SERVER, "/token :: Validated request grant_type")

      // HTTP Response Headers
      res.setHeader("Cache-Control", "no-store")
      res.setHeader("Pragma", "no-cache")

      // Generate access token and expiration time
      let tokenInfo = {}
      let d = new Date();
      let currTime = Math.round(d.getTime() / 1000)
      let accessToken = randomstring.generate(GENERATOR_SIZE)      

      // Authorization server MUST validations
      if(req.body.grant_type == "authorization_code") {
        if(storage.authCodes[req.body.code] == null || storage.authCodes[req.body.code].redirect_uri != req.body.redirect_uri) {
          // Update authorization server console logs
          utilities.updateLogs(SERVER, "/token :: Detected invalid grant. Returning error response")  
          return res.status(400).send({error: "invalid_grant", state: req.body.state})
        }
        else 
          utilities.updateLogs(SERVER, "/token :: Validated grant")  

        if(storage.authCodes[req.body.code].client_id != client.client_id) {
          // Update authorization server console logs
          utilities.updateLogs(SERVER, "/token :: Detected unauthorized client. Returning error response")
          return res.status(400).send({error: "unauthorized_client", state: req.body.state})
        }
        else 
          utilities.updateLogs(SERVER, "/token :: Validated client authorization")

        // Update authorization codes
        if(!utilities.updateAuthCodes(req.body.code)) {
          utilities.updateLogs(SERVER, "/token :: Authorization code already used once")
          return res.status(500).send({error: "server_error", state: req.body.state})
        }
        else
          utilities.updateLogs(SERVER, "/token :: Validated authorization code")              

        tokenInfo = {"token_type": "bearer", 
                    "expires_in": currTime + 3600, 
                    "refresh_token": randomstring.generate(GENERATOR_SIZE),
                    "refresh_token_expiration": currTime + 3600*24,
                    "auth_code": req.body.code,
                    "client_id": client.client_id,
                    "username": storage.authCodes[req.body.code].username,
                    "scope": storage.authCodes[req.body.code].scope
                  }
        
        // Update authorization server console logs
        utilities.updateLogs(SERVER, "/token :: Generated new access and refresh tokens. Token information :: " + JSON.stringify(tokenInfo))
      }
      else {         
        // Retrieve information associated with the refresh_token
        let oldAccessTokenInfo = utilities.validateRefreshToken(req.body.refresh_token, client.client_id) 
        utilities.updateLogs(SERVER, "/token :: Retrieve information associated with the refresh_token")  

        // Invalid refresh_token
        if(oldAccessTokenInfo == null) {
          utilities.updateLogs(SERVER, "/token :: Invalid refresh token. Returning error response")  
          return res.status(400).send({error: "invalid_refresh_token", state: req.body.state})
        }
        
        // Delete previous token
        delete storage.accessTokens[oldAccessTokenInfo.accessToken]
        utilities.updateLogs(SERVER, "/token :: Removed old access token information")  

        tokenInfo = {"token_type": "bearer", 
                    "expires_in": currTime + 3600, 
                    "refresh_token": randomstring.generate(GENERATOR_SIZE),
                    "refresh_token_expiration": currTime + 3600*24,
                    "auth_code": oldAccessTokenInfo.auth_code,
                    "client_id": client.client_id,
                    "username": oldAccessTokenInfo.username,
                    "scope": oldAccessTokenInfo.scope
                  }
        // Update authorization server console logs
        utilities.updateLogs(SERVER, "/token :: Generated new access token using the refresh token. Token information :: " + JSON.stringify(tokenInfo))
      }            
                                                
      // Update storage data
      storage.accessTokens[accessToken] = tokenInfo
      storage.updateAccessTokens()

      // Update authorization server console logs
      utilities.updateLogs(SERVER, "/token :: Returning token information back to the client")

      return res.send({access_token: accessToken,
                      token_type: storage.accessTokens[accessToken].token_type,
                      expires_in: 3600,
                      refresh_token: storage.accessTokens[accessToken].refresh_token,
                      scope: storage.accessTokens[accessToken].scope,
                      state: req.body.state
                      })
    }               
  }

  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/token :: Invalid client. Returning error response")

  res.status(400).send({error: "invalid_client", state: req.body.state})
})

/**
 * Introspection endpoint used to retrieve information about a specific token.
 * This includes client authentication to prevent token scanning attacks, also
 * known as token fishing, and is implemented according the specification in 
 * RFC 7662.
 */
app.post('/introspect', function(req, res) {
  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/introspect :: [Post][Request] :: " + JSON.stringify(req.body))

  let credentials = new Buffer.from(req.headers.authorization.split(" ")[1], 'base64').toString('ascii').split(":")

  // Client authentication to prevent token scanning attacks
  for(client of storage.clients) {    
    if(utilities.computeHash(client.client_id) == credentials[0] && utilities.computeHash(client.client_secret) == credentials[1]) {
      // Update authorization server console logs
      utilities.updateLogs(SERVER, "/introspect :: Client authenticated successfully")

      // Token variables
      let tokenInfo = storage.accessTokens[req.body.token]
      let d = new Date();
      let currTime = Math.round(d.getTime() / 1000)
      
      // Invalid/Revoked/Expired token
      if(tokenInfo == null || currTime > tokenInfo.expires_in) {
        utilities.updateLogs(SERVER, "/introspect :: Invalid/Revoked/Expired token. Returning error response")
        return res.status(200).send({active: false})
      }
      
      // Update authorization server console logs
      utilities.updateLogs(SERVER, "/introspect :: Valid token. Returning token information back to the protected resource")

      // Return token information
      return res.status(200).send({active: currTime < tokenInfo.expires_in,
                                   scope: tokenInfo.scope,
                                   client_id: tokenInfo.client_id,
                                   username: tokenInfo.username,
                                   token_type: tokenInfo.token_type,
                                   exp: tokenInfo.expires_in
                                   })
    }   
  }
  
  // Update authorization server console logs
  utilities.updateLogs(SERVER, "/introspect :: Unauthorized protected resource. Returning error response")

  res.status(401).send({error: "Unauthorized"})
})

// Initialize server
let server = app.listen(9001, 'localhost', function () {
  console.log('OAuth Authorization Server is listening at http://localhost:%s', server.address().port)
});
 
