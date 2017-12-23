/*global console, require, process */
var fs = require('fs');
var readline = require('readline');
var google = require('googleapis');
var googleAuth = require('google-auth-library');

function gsuiteOauthManager(mainSpecs) {
    "use strict";
    var scopes;
    var credentialsFile;
    var tokenFile;
    var domainAuthorisations = {};

    function storeToken(token) {
        return new Promise(function (resolve, reject) {
            fs.writeFile(tokenFile, JSON.stringify(token), function (err) {
                if (err) {
                    console.debug("Error writing the toke to %s", tokenFile);
                    return reject(err);
                }
                console.debug("Token stored to %s", tokenFile);
                return resolve();
            });
        });
    }

    function getNewToken(credentials) {
        var clientSecret = credentials.installed.client_secret;
        var clientId = credentials.installed.client_id;
        var redirectUrl = credentials.installed.redirect_uris[0];
        var auth = new googleAuth();
        var oauth2Client = new auth.OAuth2(clientId, clientSecret, redirectUrl);

        var authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopes
        });

        return new Promise(function (resolve, reject) {
            console.log('Authorize this app by visiting this url: ', authUrl);
            var rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });

            rl.question('Enter the code from that page here: ', function (code) {
                rl.close();
                oauth2Client.getToken(code, function (err, token) {
                    if (err) {
                        return reject("Error while trying to retrieve access token", err);
                    }
                    oauth2Client.credentials = token;
                    return storeToken(token).then(function () {
                        return resolve(oauth2Client);
                    }).catch(function (err) {
                        return reject(err);
                    });
                });
            });
        });
    }

    function authorize(credentials, token) {
        return new Promise(function (resolve) {
            var clientSecret = credentials.installed.client_secret;
            var clientId = credentials.installed.client_id;
            var redirectUrl = credentials.installed.redirect_uris[0];
            var auth = new googleAuth();
            var oauth2Client = new auth.OAuth2(clientId, clientSecret, redirectUrl);

            oauth2Client.credentials = token;
            return resolve(oauth2Client);
        });
    }

    function getTokenFromFile(tokenFile) {
        console.debug("loading token from the file %s", tokenFile);
        return new Promise(function (resolve, reject) {
            fs.readFile(tokenFile, function (err, token) {
                if (err) {
                    if (err.errno === -4058) {
                        return resolve(undefined);
                    }
                    return reject(err);
                }
                return resolve(JSON.parse(token));
            });
        });
    }

    function loadCredentials(credentialsFile) {
        console.debug("loading credentials from the file %s", credentialsFile);
        return new Promise(function (resolve, reject) {
            fs.readFile(credentialsFile, function (err, content) {
                if (err) {
                    return reject("Error loading client secret file: " + err);
                }
                return resolve(JSON.parse(content));
            });
        });
    }

    function getAuthorisation() {
        return new Promise(function (resolve, reject) {
            var credentials;
            // loading credentials file
            return loadCredentials(credentialsFile).then(function (response) {
                credentials = response;
                // loading token from file
                return getTokenFromFile(tokenFile);
            }).then(function (response) {
                if (response) {
                    // using token from file
                    return authorize(credentials, response).then(function (auth) {
                        console.debug("Authorized user");
                        return resolve(auth);
                    });
                }
                // creating new token
                return getNewToken(credentials).then(function (auth) {
                    console.debug("Authorized user");
                    return resolve(auth);
                });
            }).catch(function (err) {
                return reject(err);
            });
        });
    }

    function getDomainWideAuthorisation(specs) {
        var key;
        var jwtClient;
        var serviceAccountScopes;
        var user;

        key = require(specs.keyFile);
        serviceAccountScopes = specs.scopes;
        user = specs.user;

        return new Promise(function (resolve, reject) {
            if (domainAuthorisations[user] !== undefined) {
                resolve(domainAuthorisations[user]);
                return;
            }

            jwtClient = new google.auth.JWT(
                key.client_email,
                null,
                key.private_key,
                serviceAccountScopes,
                user
            );
            jwtClient.authorize(function (err) {
                if (err) {
                    console.log(err);
                    return reject("Could not authenticate " + user + ":" + err);
                }
                console.debug("Autorized %s as a service account user", user);
                domainAuthorisations[user] = jwtClient;
                return resolve(jwtClient);
            });
        });
    }

    credentialsFile = mainSpecs.credentialsFile;
    tokenFile = mainSpecs.tokenFile;
    scopes = mainSpecs.scopes;

    return {
        getAuthorisation: getAuthorisation,
        getDomainWideAuthorisation: getDomainWideAuthorisation
    };
}

module.exports = gsuiteOauthManager;