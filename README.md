# JWT-rotator

A lambda function for automatically rotation a JSON Web Token.

## How to use

1. Choose a token provider. Here are some recommended ones:

    * [SecretCredentialsTokenProvider](https://github.com/SKF/go-rest-utility/blob/master/client/auth/secrets_manager.go#L13)
    * [CredentialsTokenProvider](https://github.com/SKF/go-rest-utility/blob/master/client/auth/credentials.go#L24)
    * Write your own provider that implements
      this [interface](https://github.com/SKF/go-rest-utility/blob/master/client/auth/tokens.go#L10)


2. Create a main lambda function in your application. 
   It could look something like [this](examples/lambda/main.go). 
   

3. Configure a secret using terraform  
   TODO: Document examples