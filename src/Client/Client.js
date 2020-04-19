let axios = require('axios');
let crypto = require("crypto")
let express = require("express");
let session = require("express-session")

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
app.set('views', '../../public/Client');

app.use('/', express.static('../../public/Client'));

///////////////
// Utilities //
///////////////

/**
 * Computes an hash from the session identifier
 * @param {string} sessionID Session Identifier
 */
function computeHash(sessionID) {
  return crypto.createHash('sha256').update(sessionID).digest('hex');
}

/**
 * Initializes variables associated with current session
 * @param {object} req Request containing session
 */
function initSessionVariables(req) {
  req.session.scope = req.session.scope == null ? null : req.session.scope
  req.session.auth_code = req.session.auth_code == null ? null : req.session.auth_code
  req.session.access_token = req.session.access_token == null ? null : req.session.access_token
  req.session.refresh_token = req.session.refresh_token == null ? null : req.session.refresh_token
}

//////////////////////
// LOAD INFORMATION //
//////////////////////

// Client Information
let client = JSON.parse(require('fs').readFileSync('Data.json', 'utf8'));

// Authorization Server Endpoints
let authServerEndpoints = {
  tokenEndpoint: 'http://localhost:9001/token',
  authorizationEndpoint: 'http://localhost:9001/authorize' + "?"
                        + "response_type=code" + "&"
                        + "client_id=" + client.client_id + "&"
                        + "redirect_uri=" + client.redirect_uris[0] + "&"
                        + "scope=" + client.scope	
};

////////////
// ROUTES //
////////////

app.get('/', function (req, res) {
  // Initialize session variables
  initSessionVariables(req)  
  
  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope, 
                        auth_endpoint: authServerEndpoints.authorizationEndpoint + "&state=" + computeHash(req.sessionID)})
})

app.get('/callback', function (req, res) {
  // Validate state
  if(req.query.state != computeHash(req.sessionID))
    return res.redirect('/')

  // Update authorization code
  req.session.auth_code = req.query.code == null ? req.session.auth_code : req.query.code

  res.render('Index', { auth_code: req.session.auth_code,
                        access_token: req.session.access_token, 
                        refresh_token: req.session.refresh_token, 
                        scope: req.session.scope, 
                        auth_endpoint: authServerEndpoints.authorizationEndpoint + "&state=" + computeHash(req.sessionID)})
})

////////////////////
// TOKEN ENDPOINT //
////////////////////

// TODO 
app.get('/token', function (_, res) {  
  // Client authentication 


  axios.post(authServerEndpoints.tokenEndpoint, {
    grant_type: "authorization_code",
    code: auth_code,
    redirect_uri: client.redirect_uris[0],
    client_id: client.client_id
  })
  .then(function (response){
    console.log(response.data)
  })
  .catch(function (error) {
    console.log(error)
  })

  res.redirect('callback')
})

let server = app.listen(9000, 'localhost', function () {
  console.log('OAuth Client is listening at http://localhost:%s', server.address().port);
});
 
