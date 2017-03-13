# Cognito Lambda function

This lambda function is used as a custom authorizer for API Gateway. It:
* validates Cognito users' authentication.
* proxifies API GW calls to other lambdas functions


## API Gateway configuration

To use this lambda function, you will have to:
* create a custom authorizer on your AWS Console API Gateway
* add the authorizer to each endpoint that needs to be secured (AWS Console > Resources > select endpoint / method > select "Method Request" > select the authorizer in "Authentication Settings")

Every call to the API Gateway endpoints configured with the authorizer will require an authorization header containing an encrypted JWT token. See [Using Tokens with User Pools](http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html) to generate a Cognito JWT ID token.

## Documentation

* [API Security](https://servicesmadesimpler.govnet.qld.gov.au/wiki/pages/viewpage.action?pageId=26970091)
* [Use Amazon API Gateway Custom Authorizers](http://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html)
