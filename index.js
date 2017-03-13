console.log('Loading function');

var jwt = require('jsonwebtoken');
var request = require('request');
var jwkToPem = require('jwk-to-pem');

var userPoolId = process.env.AWS_COGNITO_USERPOOL_ID;
var region = process.env.AWS_COGNITO_USERPOOL_REGION;
var iss = 'https://cognito-idp.' + region + '.amazonaws.com/' + userPoolId;
var pems;

exports.handler = function(event, context) {
    if (!pems) {
      request({
         url: iss + '/.well-known/jwks.json',
         json: true
       }, function (error, response, body) {
          if (!error && response.statusCode === 200) {
              pems = {};
              var keys = body['keys'];
              for(var i = 0; i < keys.length; i++) {

                  var key_id = keys[i].kid;
                  var modulus = keys[i].n;
                  var exponent = keys[i].e;
                  var key_type = keys[i].kty;
                  var jwk = { kty: key_type, n: modulus, e: exponent};
                  var pem = jwkToPem(jwk);
                  pems[key_id] = pem;
              }
              ValidateToken(pems, event, context);
          } else {
              context.fail("error");
          }
      });
    } else {
        ValidateToken(pems, event, context);
    };
};

function ValidateToken(pems, event, context) {

    var token = event.authorizationToken;
    var decodedJwt = jwt.decode(token, {complete: true});

    if (!decodedJwt) {
        console.log("Not a valid JWT token");
        context.fail("Unauthorized");
        return;
    }

    if (decodedJwt.payload.iss != iss) {
        console.log("invalid issuer");
        context.fail("Unauthorized");
        return;
    }

    if (decodedJwt.payload.token_use != 'access') {
        console.log("Not an access token");
        context.fail("Unauthorized");
        return;
    }

    var kid = decodedJwt.header.kid;
    var pem = pems[kid];
    if (!pem) {
        console.log('Invalid access token');
        context.fail("Unauthorized");
        return;
    }

    jwt.verify(token, pem, { issuer: iss }, function(err, payload) {
      if(err) {
        context.fail("Unauthorized");
      } else {
        var principalId = payload.sub;
        var apiOptions = {};
        var tmp = event.methodArn.split(':');
        var apiGatewayArnTmp = tmp[5].split('/');
        var awsAccountId = tmp[4];
        apiOptions.region = tmp[3];
        apiOptions.restApiId = apiGatewayArnTmp[0];
        apiOptions.stage = apiGatewayArnTmp[1];
        var method = apiGatewayArnTmp[2];
        var resource = '/';
        if (apiGatewayArnTmp[3]) {
            resource += apiGatewayArnTmp[3];
        }
      }
    });
}
