// Client Information
exports.client = JSON.parse(require('fs').readFileSync('Client/json/Data.json', 'utf8'))

// Authorization Server Endpoints
exports.authServerEndpoints = {
  tokenEndpoint: 'http://localhost:9001/token',
  authorizationEndpoint: 'http://localhost:9001/authorize',
  introspectionEndpoint: 'http://localhost:9001/introspect'
}

// Authorization Server Endpoints
exports.protectedResourceEndpoints = {
  resourceEndpoint: 'http://localhost:9002/resource'  
}

//////////////////////////////////////
// Authorization Server Information //
//////////////////////////////////////
 
exports.clients = JSON.parse(require('fs').readFileSync('AuthServer/json/Clients.json', 'utf8')).clients
exports.rsrcOwners = JSON.parse(require('fs').readFileSync('AuthServer/json/ResourceOwners.json', 'utf8'))
exports.authCodes = JSON.parse(require('fs').readFileSync('AuthServer/json/AuthCodes.json', 'utf8'))
exports.accessTokens = JSON.parse(require('fs').readFileSync('AuthServer/json/AccessTokens.json', 'utf8'))

exports.updateAuthCodes = function() {
  require('fs').writeFileSync('AuthServer/json/AuthCodes.json', JSON.stringify(this.authCodes, null, 2))
}

exports.updateAccessTokens = function() {
  require('fs').writeFileSync('AuthServer/json/AccessTokens.json', JSON.stringify(this.accessTokens, null, 2))
}

////////////////////////////////////
// Protected Resource Information //
////////////////////////////////////

exports.tokensCache = JSON.parse(require('fs').readFileSync('ProtectedResource/json/Cache.json', 'utf8'))
exports.dictionary = JSON.parse(require('fs').readFileSync('ProtectedResource/json/Dictionary.json', 'utf8'))

exports.updateTokensCache = function() {
  require('fs').writeFileSync('ProtectedResource/json/Cache.json', JSON.stringify(this.tokensCache, null, 2))
}

exports.updateDictionary = function() {
  require('fs').writeFileSync('ProtectedResource/json/Dictionary.json', JSON.stringify(this.dictionary, null, 2))
}