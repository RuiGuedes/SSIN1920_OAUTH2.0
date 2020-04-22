let crypto = require("crypto")

/**
 * Computes an hash from the some value
 * @param {string} value some value
 */
exports.computeHash = function(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

/**
 * Validates client identifier
 * @param {string} client_id client identifier
 */
exports.validClient = function(client_id, clients) {
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
exports.validRedirectUri = function(client_id, redirect_uri, clients) {
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
exports.validScope = function(scope) {
for(elem of scope) {
    if(elem != "read" && elem != "write" && elem != "delete")
    return false
}
return scope.length > 3 ? false : true
}