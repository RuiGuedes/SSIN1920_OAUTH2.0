let crypto = require("crypto")
let express = require("express");
let bodyParser = require('body-parser')
let session = require("express-session")
let randomstring = require("randomstring");

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
app.set('views', '../../public/AuthServer');
app.set('json spaces', 4);

app.use('/', express.static('../../public/AuthServer'));

///////////////
// UTILITIES //
///////////////

/**
 * Computes an hash from the some value
 * @param {string} value some value
 */
function computeHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

//////////////////////
// LOAD INFORMATION //
//////////////////////

let clients = JSON.parse(require('fs').readFileSync('Clients.json', 'utf8')).clients;
let rsrcOwners = JSON.parse(require('fs').readFileSync('ResourceOwners.json', 'utf8'));
let authCodes = JSON.parse(require('fs').readFileSync('AuthCodes.json', 'utf8'));

// Authorization Server Information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

////////////
// ROUTES //
////////////

app.get('/', function(_, res) {
	res.render('Index', {clients: clients, authServer: authServer})
})

////////////////////
// AUTHENTICATION //
////////////////////

app.get('/authentication', function(req, res) {    
  if(req.session.userID != null)
    res.redirect('/permissions')
  else
	  res.render('Auth', {status: req.query.status == null ? "" : "Invalid credentials"})
})

app.post('/authentication', function(req, res) { 
  // Check if credentials are valid or not
  if(rsrcOwners[req.body.username] != null && computeHash(req.body.password) == rsrcOwners[req.body.username]) {    
    req.session.userID = req.body.username            
    res.redirect('/permissions') 
  }
  else
    res.redirect("/authentication?status=auth_failed")  
})

/////////////////
// PERMISSIONS // 
/////////////////

app.get('/permissions', function(req, res) {
  // Determines whether the user is authenticated or not
  if(req.session.userID == null)
    res.redirect('http://localhost:9001/')
  else
    res.render('AuthDecision', {cliend_id: req.session.request.cliend_id,
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

  authCodes[req.session.request.client_id] = {"code": auth_code, 
                                              "expiration": expiration, 
                                              "redirection_uri": req.session.request.redirect_uri,
                                              "used": false
                                            }
                                   
  // Update storage data
  require('fs').writeFileSync('AuthCodes.json', JSON.stringify(authCodes, null, 2));                 
  
  res.redirect(req.session.request.redirect_uri + "?code=" + auth_code + "&state=" + req.session.request.state)
})


///////////////
// AUTHORIZE //
///////////////

/**
 * Validates client identifier
 * @param {string} client_id client identifier
 */
function validClient(client_id) {
  for(client of clients) {
    if(client.client_id == client_id) 
      return true
  }
  return false
}

/**
 * Validates request redirect uri
 * @param {string} client_id client identifier
 * @param {string} redirect_uri request redirect uri
 */
function validRedirectUri(client_id, redirect_uri) {
  // Retrieve from storage the client redirect uris
  for(client of clients) {
    if(client.client_id == client_id) {
      for(uri of client.redirect_uris) {
        if(redirect_uri == uri)
          return true
      }
      return false
    }
  }
}

/**
 * Validate request scope
 * @param {Array} scope scope array
 */
function validScope(scope) {
  for(elem of scope) {
    if(elem != "read" && elem != "write" && elem != "delete")
      return false
  }
  return scope.length > 3 ? false : true
}

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
  if(request.response_type == null || request.client_id == null || !validRedirectUri(request.client_id, request.redirect_uri))
    res.redirect(request.redirect_uri + "?error=invalid_request&state=" + request.state)

  // Validate <response_type> 
  if(request.response_type != "code")
    res.redirect(request.redirect_uri + "?error=unsupported_response_type&state=" + request.state)

  // Validate <client_id>
  if(!validClient(request.client_id))
    res.redirect(request.redirect_uri + "?error=unauthorized_client&state=" + request.state)

  // Validate <scope> 
  if(!validScope(request.scope))
    res.redirect(request.redirect_uri + "?error=invalid_scope&state=" + request.state)

  // Authenticate resource owner
  req.session.request = request
  res.redirect('/authentication')
});

////////////////////
// TOKEN ENDPOINT //
////////////////////

app.post('/token', function(req, res) {
  
  return res.send({access_token: ""})
})

// Start server listening
let server = app.listen(9001, 'localhost', function () {
  console.log('OAuth Authorization Server is listening at http://localhost:%s', server.address().port)
});
 
