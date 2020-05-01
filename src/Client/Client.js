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
                        auth_endpoint: storage.authServerEndpoints.authorizationEndpoint + "?"
                                      + "response_type=code" + "&"
                                      + "client_id=" + storage.client.client_id + "&"
                                      + "redirect_uri=" + storage.client.redirect_uris[0] + "&"
                                      + "scope=" + storage.client.scope	 + "&state=" + utilities.computeHash(req.sessionID)})
})


app.get('/token', function (req, res) {  
  
  axios.post(storage.authServerEndpoints.tokenEndpoint, {
    grant_type: "authorization_code",
    code: req.session.auth_code,
    redirect_uri: storage.client.redirect_uris[0],
    client_id: storage.client.client_id
  }, {
    auth: {
      username: storage.client.client_id,
      password: storage.client.client_secret
    }
  })
  .then(function (response){
    req.session.access_token = response.data.access_token
    req.session.refresh_token = response.data.refresh_token
    req.session.scope = response.data.scope    
    res.redirect('/callback')
  })
  .catch(function (error) {
    res.redirect('/callback' + "?error=" + error.data.error + "&state=" + error.data.state)
  })  
})

// Initialize server
let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port);
});
 
