let crypto = require("crypto")
let storage = require("./Storage.js")

/**
 * Computes an hash from the some value
 * @param {string} value some value
 */
exports.computeHash = function(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Converts the scope from a human friendly manner 
 * to more technical point of view.
 */
exports.convertScope = function(value) {
    switch(value){
        case "Search":
            return "read"
        case "Insert":
            return "write"            
        case "Delete":
            return "delete"            
        default:
            return null
    }
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

/**
 * Updates auth codes and associated access tokens
 * @param {String} code Authorization code to be used and checked
 */
exports.updateAuthCodes = function(code) {
    // Return result status
    let status = true

    // Get current time
    let d = new Date();
    let currTime = Math.round(d.getTime() / 1000)

    for(authCode in storage.authCodes) {
        if(currTime > storage.authCodes[authCode].expiration || (storage.authCodes[authCode].used && authCode != code))
            delete storage.authCodes[authCode]        
    }
    
    // Mark authorization code as used
    if(storage.authCodes[code] != null) {
        if(storage.authCodes[code].used) {
            // Revoke all tokens issued with the authorization code
            for(accessToken in storage.accessTokens) {
                if(code == storage.accessTokens[accessToken].auth_code) {
                    delete storage.accessTokens[accessToken]
                    storage.updateAccessTokens()
                }
            }
            // Operation failed
            status = false
        }
        else
            storage.authCodes[code].used = true
    }

    // Update authCodes file
    storage.updateAuthCodes()

    // Return operation status
    return status    
}

/**
 * Revokes old authorization code(s) issued to a specific client.
 * Also revoke access tokens issued based on a certain authorization
 * code issued to that same client.
 * @param {String} client_id Client identifier
 */
exports.revokeAuthCode = function(client_id) {
    for(authCode in storage.authCodes) {
        if(client_id == storage.authCodes[authCode].client_id) {
            for(accessToken in storage.accessTokens) {        
                if(authCode == storage.accessTokens[accessToken].auth_code)
                    delete storage.accessTokens[accessToken]        
            }
            delete storage.authCodes[authCode]
        }                    
    }

    // Update storage
    storage.updateAuthCodes()
    storage.updateAccessTokens()
}

/**
 * Validates a refresh token and if valid returns the associated information. Otherwise, returns null.
 * @param {String} refresh_token Refresh token to be verified
 * @returns Refresh token associated information. Null otherwise.
 */
exports.validateRefreshToken = function(refresh_token, client_id) {
    // Validate refresh_token
    if(refresh_token == null)
        return null

    // Get current time
    let d = new Date();
    let currTime = Math.round(d.getTime() / 1000)

    // Clean expired access/refresh tokens
    for(accessToken in storage.accessTokens) {        
        if(currTime > storage.accessTokens[accessToken].expires_in || currTime > storage.accessTokens[accessToken].refresh_token_expiration)
            delete storage.accessTokens[accessToken]        
    }

    // Return status
    let status = null
    
    for(accessToken in storage.accessTokens) {
        if(refresh_token == storage.accessTokens[accessToken].refresh_token && client_id == storage.accessTokens[accessToken].client_id) {
            let tokenInfo = storage.accessTokens[accessToken]
            tokenInfo.accessToken = accessToken
            status = tokenInfo
        }
    }
    return status
}