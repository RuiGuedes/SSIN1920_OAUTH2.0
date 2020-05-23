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

let SERVER = 'Resource'

///////////////
// ENDPOINTS //
///////////////

/**
 * Default endpoint
 */
app.get('/', function(req, res) {
	res.render('index', {logs: storage.resourceLogs});
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
  // Update protected resource console logs
  utilities.updateLogs(SERVER, "/resource :: Received the following request :: " + JSON.stringify(req.body))

  // Retrieve access token from the request
  let access_token = req.headers.authorization.split(' ')[1]

  // Cleanup cache & Update protected resource console logs
  utilities.cleanupTokensCache()
  utilities.updateLogs(SERVER, "/resource :: Cleanup cache")

  // Update protected resource console logs
  utilities.updateLogs(SERVER, "/resource :: [Post][Request][" + storage.authServerEndpoints.introspectionEndpoint + "] ::" + JSON.stringify({token: access_token}))

  // Determine whether the pretended token is cached or not
  if(storage.tokensCache[access_token] == null) {
    axios.post(storage.authServerEndpoints.introspectionEndpoint, {token: access_token}, {
      auth: {
        username: storage.resource.resource_id,
        password: storage.resource.resource_secret
      }
    })
    .then(function (response){
      // Update protected resource console logs
      utilities.updateLogs(SERVER, "/resource :: [Post][Response][" + storage.authServerEndpoints.introspectionEndpoint + "] ::" + JSON.stringify(response.data))

      // Update cache storage      
      storage.tokensCache[access_token] = response.data
      storage.updateTokensCache()
      utilities.updateLogs(SERVER, "/resource :: Update cache storage")
      
      // Verify according the token cached information if operation is valid and execute it       
      return res.status(200).send(utilities.accessResource(access_token, req.body))      
    })
    .catch(function (error) {
      // Update protected resource console logs
      utilities.updateLogs(SERVER, "/resource :: [Post][Response][" + storage.authServerEndpoints.introspectionEndpoint + "] ::" + JSON.stringify(error.response.data))   
      return res.status(400).send({error: error.response.data.error})    
    })    
  }
  else
    return res.status(200).send(utilities.accessResource(access_token, req.body))
    
})

// Initialize server
let server = app.listen(9002, 'localhost', function () {
  console.log('OAuth Resource Server is listening at http://localhost:%s', server.address().port)
});
 
