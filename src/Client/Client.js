let axios = require('axios')
let express = require("express")
let base64url = require('base64url')
let session = require("express-session")
let utilities = require("../Utilities.js")
let storage = require("../Storage.js")
let bodyParser = require('body-parser')
let randomstring = require("randomstring")

////////////////
// APP CONFIG //
////////////////

let app = express()

app.use(session({
  secret: 'oauth-client-secret',
  name: 'client-session',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug')
app.set('views', '../public/Client')

app.use('/', express.static('../public/Client'))

////////////
// GLOBAL //
////////////

let SERVER = 'Client'
let GENERATOR_SIZE = 256

// Create code_verifier
storage.client.code_verifier = randomstring.generate(GENERATOR_SIZE)

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function (req, res) {
  // Add error to the console log
  if(req.query.error != null)
    utilities.updateLogs(SERVER, "/callback :: Detected the following error: " + req.query.error)

  // Update client console logs
  utilities.updateLogs(SERVER, "/ :: Loading default endpoint")

  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope, 
                        error: req.query.error,
                        info: req.query.info,
                        logs: storage.clientLogs,
                        auth_endpoint: storage.authServerEndpoints.authorizationEndpoint + "?"
                                      + "response_type=code" + "&"
                                      + "client_id=" + storage.client.client_id + "&"
                                      + "redirect_uri=" + storage.client.redirect_uris[0] + "&"
                                      + "scope=" + storage.client.scope	 + "&state=" + utilities.computeHash(req.sessionID) + "&"
                                      + "code_challenge=" + base64url(utilities.computeHash(storage.client.code_verifier)) + "&"
                                      + "code_challenge_method=S256"
                        }
            )
})

/**
 * Callback endpoint which corresponds to the client redirection uri that 
 * is passed in every request to the authorization server.
 */
app.get('/callback', function (req, res) {
  // Validate redirection through validation of the state 
  if(req.query.state != utilities.computeHash(req.sessionID)) {
    // Update client console logs
    utilities.updateLogs(SERVER, "/callback :: State parameter do not match the current session ID. Possibility of CSRF attack")
    
    return res.redirect('/')
  }

  // Update authorization code
  if(req.query.code != null) {
    // Update client console logs
    utilities.updateLogs(SERVER, "/callback :: Received new authorization code: " + req.query.code)
    utilities.updateLogs(SERVER, "/callback :: Revoked old access and refresh tokens")

    req.session.auth_code = req.query.code
    req.session.access_token = req.session.refresh_token = req.session.scope = null
  }
  
  // Add error to the console log
  if(req.query.error != null)
    utilities.updateLogs(SERVER, "/callback :: Detected the following error: " + req.query.error)

  // Update client console logs
  utilities.updateLogs(SERVER, "/callback :: Loading callback endpoint")

  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope,
                        error: req.query.error,
                        info: req.query.info,
                        logs: storage.clientLogs,
                        auth_endpoint: storage.authServerEndpoints.authorizationEndpoint + "?"
                                      + "response_type=code" + "&"
                                      + "client_id=" + storage.client.client_id + "&"
                                      + "redirect_uri=" + storage.client.redirect_uris[0] + "&"
                                      + "scope=" + storage.client.scope	 + "&state=" + utilities.computeHash(req.sessionID) + "&"
                                      + "code_challenge=" + base64url(utilities.computeHash(storage.client.code_verifier)) + "&"
                                      + "code_challenge_method=S256"
                      }
            )
})

/**
 * Endpoint used to request a new access token
 */
app.get('/token', function (req, res) { 
  // Construct request body 
  let body = {}

  // Determine whether it must refresh the access token or not
  if(req.session.refresh_token != null) {
    body.grant_type = "refresh_token"
    body.refresh_token = req.session.refresh_token 
    
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Request][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(body))
  }
  else {    
    body.grant_type = "authorization_code"
    body.code = req.session.auth_code
    body.redirect_uri = storage.client.redirect_uris[0]
    body.code_verifier = storage.client.code_verifier
    
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Request][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(body))
  }  

  // Send POST request to the token endpoint with confidential client authentication
  axios.post(storage.authServerEndpoints.tokenEndpoint, body, {    
    auth: {
      username: storage.client.client_id,
      password: storage.client.client_secret
    }
  })
  .then(function (response){
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(response.data))

    req.session.access_token = response.data.access_token
    req.session.refresh_token = response.data.refresh_token
    req.session.scope = response.data.scope    
    res.redirect('/')
  })
  .catch(function (error) {
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(error.response.data))

    req.session.auth_code = req.session.access_token = req.session.refresh_token = req.session.scope = null
    res.redirect('/?error=' + error.response.data.error)
  })  
})

/**
 * Endpoint used to access the protected resource
 */
app.get('/resource', function(req, res) {
  // Validate GET request
  if (req.query.word == "" || !/^[a-zA-Z0-9]+$/.test(req.query.word) || utilities.convertScope(req.query.submit) == null ||
     (req.query.submit == "Insert / Replace" && (req.query.meaning == "" || !/^[a-zA-Z0-9\s]+$/.test(req.query.meaning))))
    return res.redirect('/?error=invalid_request')

  // Construct request body 
  let body = {    
    client_id: storage.client.client_id,
    action: {
      word: req.query.word,
      meaning: req.query.meaning == null ? "" : req.query.meaning,
      scope: utilities.convertScope(req.query.submit)
    }
  }
  
  // Update client console logs
  utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(body))

  // Send POST request to the protected resource
  axios.post(storage.protectedResourceEndpoints.resourceEndpoint, body, {
    headers: {
      'Authorization': `Bearer ${req.session.access_token}`
    }
  })
  .then(function (response){  
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(response.data))

    if(response.data.info == null)
      return res.redirect("/?error=forbidden")
    else      
      return res.redirect('/?info=' + response.data.info)
  })
  .catch(function (error) {       
    // Update client console logs 
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(error.response.data))
    
    res.redirect('/?error=' + error.response.data.error)
  })  
})

// Initialize server
let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port)
});
