let express = require("express");
let session = require("express-session")
let bodyParser = require('body-parser');
let crypto = require("crypto")

// App configuration
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

let codes = {}
let requests = {}

// Authorization Server Information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize?',
	tokenEndpoint: 'http://localhost:9001/token'
};

// Load Clients and Resource Owners Information
let clients = JSON.parse(require('fs').readFileSync('Clients.json', 'utf8')).clients;
let rsrc_owners = JSON.parse(require('fs').readFileSync('ResourceOwners.json', 'utf8'));

/**
 * Computes an hash from the some value
 * @param {string} value some value
 */
function computeHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Validates client identifier
 * @param {string} client_id client identifier
 */
function valid_client(client_id) {
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
function valid_redirect_uri(client_id, redirect_uri) {
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
function valid_scope(scope) {
  for(elem of scope) {
    if(elem != "read" && elem != "write" && elem != "delete")
      return false
  }
  return scope.length > 3 ? false : true
}

////////////
// Routes //
////////////

app.get('/', function(req, res) {
	res.render('Index', {clients: clients, authServer: authServer})
})

////////////////////
// AUTHENTICATION //
////////////////////

app.get('/authentication', function(req, res) {    
	res.render('Auth', {status: req.query.status == null ? "" : "Invalid credentials"})
})

app.post('/authentication', function(req, res) {
  let username = req.body.username
  let password = req.body.password
  
  for(owner in rsrc_owners) {
    if(username == owner && computeHash(password) == rsrc_owners[owner]) {
      req.session.userID = username      
      res.redirect('http://localhost:9001/permissions')      
    }  
  }  
  res.redirect("http://localhost:9001/authentication?status=auth_failed")  
})

/////////////////
// PERMISSIONS // 
/////////////////

app.get('/permissions', function(req, res) {
  if(req.session.userID == null)
    res.redirect('http://localhost:9001/')
  else
    res.render('AuthDecision', {cliend_id: req.session.request.cliend_id, 
                                deny_uri: req.session.request.redirect_uri + "?error=access_denied&state=" + req.session.request.state
                                })
})



///////////////
// AUTHORIZE //
///////////////

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
  if(request.response_type == null || request.client_id == null || !valid_redirect_uri(request.client_id, request.redirect_uri))
    res.redirect(request.redirect_uri + "?error=invalid_request&state=" + request.state)

  // Validate <response_type> 
  if(request.response_type != "code")
    res.redirect(request.redirect_uri + "?error=unsupported_response_type&state=" + request.state)

  // Validate <client_id>
  if(!valid_client(request.client_id))
    res.redirect(request.redirect_uri + "?error=unauthorized_client&state=" + request.state)

  // Validate <scope> 
  if(!valid_scope(request.scope))
    res.redirect(request.redirect_uri + "?error=invalid_scope&state=" + request.state)

  // Authenticate resource owner
  req.session.request = request
  res.redirect('http://localhost:9001/authentication')
});

app.use('/', express.static('../../public/AuthServer'));

let server = app.listen(9001, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', 'localhost', port);
});
 
