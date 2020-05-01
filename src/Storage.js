// Client Information
exports.client = JSON.parse(require('fs').readFileSync('Client/json/Data.json', 'utf8'))

// Authorization Server Endpoints
exports.authServerEndpoints = {
  tokenEndpoint: 'http://localhost:9001/token',
  clientAuth: 'http://localhost:9001/client_authentication',
  authorizationEndpoint: 'http://localhost:9001/authorize'
}

//////////////////////////////////////
// Authorization Server Information //
//////////////////////////////////////
 
exports.clients = JSON.parse(require('fs').readFileSync('AuthServer/json/Clients.json', 'utf8')).clients;
exports.rsrcOwners = JSON.parse(require('fs').readFileSync('AuthServer/json/ResourceOwners.json', 'utf8'));
exports.authCodes = JSON.parse(require('fs').readFileSync('AuthServer/json/AuthCodes.json', 'utf8'));
exports.accessTokens = JSON.parse(require('fs').readFileSync('AuthServer/json/AccessTokens.json', 'utf8'));

// Authorization Server Information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};