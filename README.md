G Suite oauth manager
=========

A helper for authenticating with the APIs

## Installation

  `npm install gsuite-oauth-manager`

## Usage

    oauthManager = gsuiteOauthManager({});

    gsuiteOauthManager({
        tokenFile: "path to token file,
        credentialsFile: "path to credentials file"),
        scopes: ["requested scopes"]
    }).getAuthorisation();

## Tests

  `npm test`

## Contributing

In lieu of a formal style guide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code.
