let axios = require('axios');
let express = require("express");
let session = require("express-session")
let utilities = require("../Utilities.js")
let storage = require("../Storage.js")

////////////////
// APP CONFIG //
////////////////

let app = express();

app.use(session({
  secret: 'oauth-client-secret',
  name: 'client-session',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../public/Client');

app.use('/', express.static('../public/Client'));

///////////////
// ENDPOINTS //
///////////////

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

app.get('/callback', function (req, res) {
  // Validate redirection through validation of the state 
  if(req.query.state != utilities.computeHash(req.sessionID))
    return res.redirect('/')

  // Update authorization code
  req.session.auth_code = req.query.code == null ? req.session.auth_code : req.query.code

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

  // Send post request to the token endpoint with confidential client authentication
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

// Initialize server
let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port);
});
 
