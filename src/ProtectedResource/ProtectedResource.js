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
  let credentials = new Buffer.from(req.headers.authorization.split(" ")[1], 'base64').toString('ascii').split(":")

  // Cleanup cache
  utilities.cleanupTokensCache()

  // Determine whether the pretended token is cached or not
  if(storage.tokensCache[req.body.token] == null) {
    axios.post(storage.authServerEndpoints.introspectionEndpoint, {token: req.body.token}, {
      auth: {
        username: credentials[0],
        password: credentials[1]
      }
    })
    .then(function (response){
      // Update cache storage
      storage.tokensCache[req.body.token] = response.data
      storage.updateTokensCache()
    })
    .catch(function (error) {
      return res.status(400).send({error: error.response.data.error, state: req.body.state})    
    })    
  }
  
  // Verify according the token cached information if operation is valid
  console.log(req.body.scope)
})

// Initialize server
let server = app.listen(9002, 'localhost', function () {
  console.log('OAuth Resource Server is listening at http://localhost:%s', server.address().port)
});
 
