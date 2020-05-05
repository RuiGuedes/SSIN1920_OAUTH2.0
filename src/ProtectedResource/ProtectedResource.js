let axios = require('axios')
let express = require("express")
let storage = require("../Storage.js")
let bodyParser = require('body-parser')
let session = require("express-session")
let randomstring = require("randomstring")
let utilities = require("../Utilities.js")

////////////////
// APP CONFIG //
////////////////

let app = express()

app.use(session({
  secret: 'oauth-auth-secret',
  name: 'auth-session',
  resave: 'false',
  saveUninitialized: 'false'
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../public/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('../public/protectedResource'));

////////////
// GLOBAL //
////////////

let resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function(req, res) {
	res.render('index', {});
});

app.post('/resource', function(req, res) {
  console.log(req.body)
})


// Initialize server
let server = app.listen(9002, 'localhost', function () {
  console.log('OAuth Resource Server is listening at http://localhost:%s', server.address().port)
});
 
