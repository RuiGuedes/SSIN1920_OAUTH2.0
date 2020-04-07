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

// Authorization Server Information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize?',
	tokenEndpoint: 'http://localhost:9001/token'
};

// Load Client Information
let clients = JSON.parse(require('fs').readFileSync('Clients.json', 'utf8')).clients;

let codes = {};

let requests = {};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get('/authorize', function(req, res) {
	
});

app.use('/', express.static('../../public/AuthServer'));

let server = app.listen(9001, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
