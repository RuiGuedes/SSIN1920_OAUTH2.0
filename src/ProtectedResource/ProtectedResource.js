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

/**
 * Grants access to the protected resource if the token is valid. At first,
 * it checks whether the token is cached or not. If the token is not cached 
 * it makes a POST request to the instrospection endpoint to validate and 
 * retrieve the token information and caches it. Then with the token information
 * available it checks whether the desired operation is possible. If it is, it 
 * is executed successfully, otherwise it returns an error.
 */
app.post('/resource', function(req, res) {
  axios.post(storage.authServerEndpoints.introspectionEndpoint, {token: req.body.token}, {
    auth: {
      username: storage.protectedResource.protected_rsrc_id,
      password: storage.protectedResource.protected_rsrc_secret
    }
  })
  .then(function (response){
    // Analyse response bla bla bla  
    //res.redirect(req.body.redirect_uri + '?state=' + response.data.state)
  })
  .catch(function (error) {        
    //res.redirect('/callback?error=' + error.response.data.error + "&state=" + error.response.data.state)
  })    
})


// Initialize server
let server = app.listen(9002, 'localhost', function () {
  console.log('OAuth Resource Server is listening at http://localhost:%s', server.address().port)
});
 
