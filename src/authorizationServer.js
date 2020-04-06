let express = require("express");
let bodyParser = require('body-parser');
let cons = require('consolidate');
let __ = require('underscore');
__.string = require('underscore.string');

let app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', '../html/authorizationServer');
app.set('json spaces', 4);

// authorization server information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
let clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "foo bar"
	}
];

let codes = {};

let requests = {};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.use('/', express.static('files/authorizationServer'));

let server = app.listen(9001, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
