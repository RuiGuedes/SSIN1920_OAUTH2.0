let express = require("express");
let session = require("express-session")
let crypto = require("crypto")

// App configuration
let app = express();

app.use(session({
  secret: 'oauth-client-secret',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../../public/client');

// Load Clients Information
let client = JSON.parse(require('fs').readFileSync('Data.json', 'utf8'));

// Authorization Server Endpoints
let authServerEndpoints = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

let access_token = null;
let refresh_token = null;
let scope = null;

/**
 * Computes an hash from the session identifier
 * @param {string} sessionID Session Identifier
 */
function computeHash(sessionID) {
  return crypto.createHash('sha256').update(sessionID).digest('hex');
}

app.get('/', function (req, res) {
  let uri = authServerEndpoints.authorizationEndpoint + "?"
            + "response_type=code" + "&"
            + "client_id=" + client.client_id + "&"
            + "redirect_uri=" + client.redirect_uris[0] + "&"
            + "scope=" + client.scope + "&"
            + "state=" + computeHash(req.sessionID);

  console.log('Root: ' + req.sessionID);

  res.render('index', { access_token: access_token, refresh_token: refresh_token, scope: scope, auth_endpoint: uri })
})

app.get('/callback', function (req, res) {
  console.log('Callback: ' + req.sessionID);

  res.render('index', { access_token: access_token, refresh_token: refresh_token, scope: scope })
})

app.use('/', express.static('../../public/client'));

let server = app.listen(9000, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
