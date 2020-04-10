let express = require("express");
let bodyParser = require('body-parser');
let __ = require('underscore');
__.string = require('underscore.string');

let app = express();

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

// Load Clients Information
let clients = JSON.parse(require('fs').readFileSync('Clients.json', 'utf8')).clients;

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

app.get('/', function(req, res) {
	res.render('auth', {clients: clients, authServer: authServer})
})

app.get('/authentication', function(req, res) {
	res.render('auth', {clients: clients, authServer: authServer})
})

app.post('/authentication', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer})
})

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
  res.redirect('/authentication')
});


app.use('/', express.static('../../public/AuthServer'));

let server = app.listen(9001, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
