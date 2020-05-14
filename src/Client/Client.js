let axios = require('axios')
let express = require("express")
let session = require("express-session")
let utilities = require("../Utilities.js")
let storage = require("../Storage.js")
let bodyParser = require('body-parser')

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

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function (req, res) {
  // Update client console logs
  utilities.updateLogs(SERVER, "/ :: Loading default endpoint")
  
  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope, 
                        logs: storage.clientLogs,
                        auth_endpoint: storage.authServerEndpoints.authorizationEndpoint + "?"
                                      + "response_type=code" + "&"
                                      + "client_id=" + storage.client.client_id + "&"
                                      + "redirect_uri=" + storage.client.redirect_uris[0] + "&"
                                      + "scope=" + storage.client.scope	 + "&state=" + utilities.computeHash(req.sessionID)})
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
  else 
    req.session.auth_code = req.session.auth_code

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
                                      + "scope=" + storage.client.scope	 + "&state=" + utilities.computeHash(req.sessionID)})
})

/**
 * Endpoint used to request a new access token
 */
app.get('/token', function (req, res) { 
  // Construct request body 
  let body = {    
    state: utilities.computeHash(req.sessionID)
  }

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
    
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Request][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(body))
  }  

  // Send POST request to the token endpoint with confidential client authentication
  axios.post(storage.authServerEndpoints.tokenEndpoint, body, {
    auth: {
      username: utilities.computeHash(storage.client.client_id),
      password: utilities.computeHash(storage.client.client_secret)
    }
  })
  .then(function (response){
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(response.data))

    req.session.access_token = response.data.access_token
    req.session.refresh_token = response.data.refresh_token
    req.session.scope = response.data.scope    
    res.redirect('/callback?state=' + response.data.state)
  })
  .catch(function (error) {
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.authServerEndpoints.tokenEndpoint + "] :: " + JSON.stringify(response.data))

    req.session.auth_code = req.session.access_token = req.session.refresh_token = req.session.scope = null
    res.redirect('/callback?error=' + error.response.data.error + "&state=" + error.response.data.state)
  })  
})

/**
 * Endpoint used to access the protected resource
 */
app.get('/resource', function(req, res) {
  // Validate GET request
  if(req.query.word == "" || !/^[a-zA-Z]+$/.test(req.query.word) || utilities.convertScope(req.query.submit) == null || 
    (req.query.submit == "Insert / Replace" && (req.query.meaning == "" || !/^[a-zA-Z\s]+$/.test(req.query.meaning)))) 
    return res.redirect('/callback?error=invalid_request&state=' + utilities.computeHash(req.sessionID))

  // Construct request body 
  let body = {    
    token: req.session.access_token,
    client_id: storage.client.client_id,
    action: {
      word: req.query.word,
      meaning: req.query.meaning == null ? "" : req.query.meaning,
      scope: utilities.convertScope(req.query.submit)
    },
    state: utilities.computeHash(req.sessionID)
  }
  
  // Update client console logs
  utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(body))

  // Send POST request to the protected resource
  axios.post(storage.protectedResourceEndpoints.resourceEndpoint, body,  {
    auth: {
      username: utilities.computeHash(storage.client.client_id),
      password: utilities.computeHash(storage.client.client_secret)
    }
  })
  .then(function (response){  
    // Update client console logs
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(response.data))

    if(response.data.info == null)
      return res.redirect("/callback?error=forbidden&state=" + error.response.data.state)
    else      
      return res.redirect('/callback?info=' + response.data.info + '&state=' + response.data.state)
  })
  .catch(function (error) {       
    // Update client console logs 
    utilities.updateLogs(SERVER, "/token :: [Post][Response][" + storage.protectedResourceEndpoints.resourceEndpoint + "] :: " + JSON.stringify(error.response.data))
    
    res.redirect('/callback?error=' + error.response.data.error + "&state=" + error.response.data.state)
  })  
})

// Initialize server
let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port)
});