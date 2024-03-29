# Google reCAPTCHA API Gateway REST API authorizer

This construct provides an API Gateway REST API authorizer that uses Google's reCAPTCHA service to detect abusive
traffic and allow or deny access to the API methods.

It currently only supports v3 of the reCAPTCHA service.

## Installation

### TypeScript / JavaScript

`npm install cdk-recaptcha-authorizer`

or

`yarn add cdk-recaptcha-authorizer`

### Python

`pip install cdk-recaptcha-authorizer`

### Java

```xml
<dependency>
    <groupId>com.engineal.cdk</groupId>
    <artifactId>cdk-recaptcha-authorizer</artifactId>
</dependency>
```

### C# / .Net

`dotnet add package EngineAL.CDK.RecaptchaAuthorizer`

## Usage

See https://developers.google.com/recaptcha/docs/v3 for how to integrate reCAPTCHA in your client code. When
your client code executes the reCAPTCHA client, the returned token from the Google reCAPTCHA client library
should be included in the API Gateway request in the `X-reCAPTCHA-Token` header.

The `RecaptchaAuthorizer` can be used similarly to the `TokenAuthorizer` and `RequestAuthorizer` that are
provided by the `aws-cdk-lib/aws-apigateway` package. It accepts 3 properties:

* `scoreThreshold` (default: 0.5) is the threshold below which requests will be denied.
* `allowedActions` is a list of allowed actions. When your frontend executes the reCAPTCHA client, it provides
an action name. The reCAPTCHA authorizer will verify this action is allowed and deny a request if the action
is not in this list.
* `reCaptchaSecretKey` is a `SecretKey` that provides the reCAPTCHA secret key to the reCAPTCHA authorizer.
See [Secret Key](secret-key).

The following code attaches the reCAPTCHA authorizer to the 'GET' method of the root resource.
```typescript
const authorizer = new RecaptchaAuthorizer(this, 'reCaptchaAuthorizer', {
    allowedActions: ['my-action'],
    reCaptchaSecretKey: SecretKey.fromPlainText('my-secret-key')
});

api.root.addMethod('GET', new apigateway.MockIntegration(), {
    authorizer
});
```

Authorizers can also be passed via the `defaultMethodOptions` property within the RestApi construct or the
Method construct. Unless explicitly overridden, the specified defaults will be applied across all Methods
across the RestApi or across all Resources, depending on where the defaults were specified.

### Secret Key
The lambda requires the secret key generated by the Google reCAPTCHA Admin Console. You can provide it using
3 methods: plain text, AWS SSM Parameter Store, or AWS Secrets Manager.

#### Plain text
```typescript
SecretKey.fromPlainText('my-secret-key')
```

#### SSM Parameter Store
```typescript
const parameter = ssm.StringParameter.fromStringParameterName(this, 'TestParameter', 'test-secret-key');
SecretKey.fromSsmParameter(parameter)
```

#### Secrets Manager
```typescript
const secretArn = `arn:${Stack.of(this).partition}:secretsmanager:${Stack.of(this).region}:${Stack.of(this).account}:secret:test-secret`;
const secret = secretsmanager.Secret.fromSecretArn(this, 'TestSecret', secretArn);
SecretKey.fromSecretsManager(secret)
```

This also supports JSON secrets, and you can specify an optional field to use:.
```typescript
const secretArn = `arn:${Stack.of(this).partition}:secretsmanager:${Stack.of(this).region}:${Stack.of(this).account}:secret:test-secret`;
const secret = secretsmanager.Secret.fromSecretArn(this, 'TestSecret', secretArn);
SecretKey.fromSecretsManager(secret, 'my-secret-field')
```

### Useful commands

 * `npm run build`   compile the project
 * `npm run watch`   watch for changes and compile as needed
 * `npm run package` generates libraries for all languages
 * `npm run test`    perform the jest unit tests

## License

   Copyright 2023 Aaron Lucia

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
