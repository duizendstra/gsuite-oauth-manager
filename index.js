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
        fs.writeFile(tokenFile, JSON.stringify(token));
        console.log('Token stored to ' + tokenFile);
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
                        reject("Error while trying to retrieve access token", err);
                        return;
                    }
                    oauth2Client.credentials = token;
                    storeToken(token);
                    resolve(oauth2Client);
                });
            });
        });
    }

    function authorize(credentials, token) {
        return new Promise(function (resolve, reject) {
            var clientSecret = credentials.installed.client_secret;
            var clientId = credentials.installed.client_id;
            var redirectUrl = credentials.installed.redirect_uris[0];
            var auth = new googleAuth();
            var oauth2Client = new auth.OAuth2(clientId, clientSecret, redirectUrl);

            oauth2Client.credentials = token;
            resolve(oauth2Client);
        });
    }

    function getTokenFromFile(tokenFile) {
        return new Promise(function (resolve) {
            fs.readFile(tokenFile, function (err, token) {
                if (err) {
                    resolve();
                } else {
                    resolve(JSON.parse(token));
                }
            });
        });
    }

    function loadCredentials(credentialsFile) {
        console.log("loading credentials from file");
        return new Promise(function (resolve, reject) {
            try {
                fs.readFile(credentialsFile, function (err, content) {
                    if (err) {
                        reject("Error loading client secret file: " + err);
                        return;
                    }
                    resolve(JSON.parse(content));
                    return;
                });
            } catch (e) {
                reject("Error loading client secret file: " + e);
            }
        });
    }

    function getAuthorisation() {
        return new Promise(function (resolve, reject) {
            var credentials;
            // loading credentials file
            loadCredentials(credentialsFile)
                .then(function (response) {
                    credentials = response;
                    // loading token from file
                    getTokenFromFile(tokenFile)
                        .then(function (response) {
                            if (response) {
                                // using token from file
                                authorize(credentials, response).then(function (auth) {
                                    console.log("Authorized user");
                                    resolve(auth);
                                    return;
                                }).catch(reject);
                            } else {
                                // creating new token
                                getNewToken(credentials).then(function (auth) {
                                    console.log("Authorized user");
                                    resolve(auth);
                                }).catch(reject);
                            }
                        }).catch(reject);
                }).catch(reject);
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
                    reject("Could not authenticate " + user + ":" + err);
                    return;
                }
                console.log("Autorized %s as a service account user", user);
                domainAuthorisations[user] = jwtClient;
                resolve(jwtClient);
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