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

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function (req, res) {  
  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope, 
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
  if(req.query.state != utilities.computeHash(req.sessionID))
    return res.redirect('/')

  // Update authorization code
  if(req.query.code != null) {
    req.session.auth_code = req.query.code
    req.session.access_token = req.session.refresh_token = req.session.scope = null
  }
  else 
    req.session.auth_code = req.session.auth_code

  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope,
                        error: req.query.error,
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
  }
  else {
    body.grant_type = "authorization_code"
    body.code = req.session.auth_code
    body.redirect_uri = storage.client.redirect_uris[0]
  }

  // Send POST request to the token endpoint with confidential client authentication
  axios.post(storage.authServerEndpoints.tokenEndpoint, body, {
    auth: {
      username: storage.client.client_id,
      password: storage.client.client_secret
    }
  })
  .then(function (response){
    req.session.access_token = response.data.access_token
    req.session.refresh_token = response.data.refresh_token
    req.session.scope = response.data.scope    
    res.redirect('/callback?state=' + response.data.state)
  })
  .catch(function (error) {    
    req.session.auth_code = req.session.access_token = req.session.refresh_token = req.session.scope = null
    res.redirect('/callback?error=' + error.response.data.error + "&state=" + error.response.data.state)
  })  
})

// localhost:9000/resource?word=Success&submit=Search
app.get('/resource', function(req, res) {
  // Validate GET request
  if(req.query.word == null || req.query.submit == null || !/^[a-zA-Z]+$/.test(req.query.word))
    return res.redirect('/callback?error=invalid_request&state=' + utilities.computeHash(req.sessionID))
  
  // Construct request body 
  let body = {    
    token: "drNV3x3vR6SazqsmVQO3pf8piVnwlzxUbuCGK95D4zwMDgQGcM283grCvPjvYiGD", // req.session.access_token,
    client_id: storage.client.client_id,
    action: {
      word: req.query.word,
      scope: req.query.submit
    },
    state: utilities.computeHash(req.sessionID)
  }
  
  // Send POST request to the protected resource
  axios.post(storage.protectedResourceEndpoints.accessEndpoint, body).then(function (response){
      //console.log(response.data)
      res.redirect('/callback?state=' + response.data.state)
  })
  .catch(function (error) {        
    res.redirect('/callback?error=' + error.response.data.error + "&state=" + error.response.data.state)
  })  
})

// Initialize server
let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port)
});
 
// TODO 
// Add authentiction between servers with hashing the password and ID
// Duplicated endpoints refactor when adding the introspection endpoint
// Add introspection endpoint 
//   - Must do all verifications
//   - Prevent token fishing with client authentication
//   - Implement caching to boost performance but still be robust (exp)
//   - 