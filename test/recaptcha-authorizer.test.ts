import {expect as expectCDK, haveResource} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as apigateway from '@aws-cdk/aws-apigateway';
import * as secretsmanager from "@aws-cdk/aws-secretsmanager";
import * as ssm from "@aws-cdk/aws-ssm";
import * as RecaptchaAuthorizer from '../lib/recaptcha-authorizer';
import {SecretKey} from "../lib";

test('Lambda Function Created with plain text secret key', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret')
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    expectCDK(stack).to(haveResource("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "nodejs12.x",
        "Environment": {
            "Variables": {
                "ALLOWED_ACTIONS": "[\"test-action\"]",
                "SECRET_KEY_TYPE": "PLAIN_TEXT",
                "SECRET_KEY": "secret"
            }
        }
    }));
});

test('Lambda Function Created with ssm secret key', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    const secretKeyParameter = ssm.StringParameter.fromSecureStringParameterAttributes(stack, 'TestParameter', {
        parameterName: 'test-secret-key',
        version: 1
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSsmParameter(secretKeyParameter)
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    expectCDK(stack).to(haveResource("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "nodejs12.x",
        "Environment": {
            "Variables": {
                "ALLOWED_ACTIONS": "[\"test-action\"]",
                "SECRET_KEY_TYPE": "SSM_PARAMETER",
                "SECRET_KEY_PARAMETER": "test-secret-key"
            }
        }
    }));
});

test('Lambda Function Created with secrets manager secret key', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret)
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    expectCDK(stack).to(haveResource("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "nodejs12.x",
        "Environment": {
            "Variables": {
                "ALLOWED_ACTIONS": "[\"test-action\"]",
                "SECRET_KEY_TYPE": "SECRETS_MANAGER",
                "SECRET_KEY_SECRET_ARN": {
                    "Fn::Join": [
                        "",
                        [
                            "arn:",
                            {
                                "Ref": "AWS::Partition"
                            },
                            ":secretsmanager:",
                            {
                                "Ref": "AWS::Region"
                            },
                            ":",
                            {
                                "Ref": "AWS::AccountId"
                            },
                            ":secret:test-secret"
                        ]
                    ]
                }
            }
        }
    }));
});

test('Lambda Function Created with secrets manager and json field', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret, 'test-field')
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    expectCDK(stack).to(haveResource("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "nodejs12.x",
        "Environment": {
            "Variables": {
                "ALLOWED_ACTIONS": "[\"test-action\"]",
                "SECRET_KEY_TYPE": "SECRETS_MANAGER",
                "SECRET_KEY_SECRET_ARN": {
                    "Fn::Join": [
                        "",
                        [
                            "arn:",
                            {
                                "Ref": "AWS::Partition"
                            },
                            ":secretsmanager:",
                            {
                                "Ref": "AWS::Region"
                            },
                            ":",
                            {
                                "Ref": "AWS::AccountId"
                            },
                            ":secret:test-secret"
                        ]
                    ]
                },
                "SECRET_KEY_FIELD": "test-field"
            }
        }
    }));
});

test('Request Authorizer Created', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret')
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    expectCDK(stack).to(haveResource("AWS::ApiGateway::Authorizer", {
        "Type": "REQUEST",
        "AuthorizerUri": {
            "Fn::Join": [
                "",
                [
                    "arn:",
                    {
                        "Ref": "AWS::Partition"
                    },
                    ":apigateway:",
                    {
                        "Ref": "AWS::Region"
                    },
                    ":lambda:path/2015-03-31/functions/",
                    {
                        "Fn::GetAtt": [
                            "TestAuthorizerfunction3F10EDDB",
                            "Arn"
                        ]
                    },
                    "/invocations"
                ]
            ]
        },
        "IdentitySource": "method.request.header.X-reCAPTCHA-Token"
    }).and(haveResource("AWS::ApiGateway::Method", {
        "AuthorizationType": "CUSTOM",
        "AuthorizerId": {
            "Ref": "TestAuthorizer64D89012"
        }
    })));
});

test('SSM parameter read granted', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    const secretKeyParameter = ssm.StringParameter.fromSecureStringParameterAttributes(stack, 'TestParameter', {
        parameterName: 'test-secret-key',
        version: 1
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSsmParameter(secretKeyParameter)
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    // TODO: check for allow to secret
    expectCDK(stack).to(haveResource("AWS::IAM::Policy", {
        "PolicyDocument": {
            "Statement": [
                {
                    "Action": [
                        "ssm:DescribeParameters",
                        "ssm:GetParameters",
                        "ssm:GetParameter",
                        "ssm:GetParameterHistory"
                    ],
                    "Effect": "Allow",
                    "Resource": {
                        "Fn::Join": [
                            "",
                            [
                                "arn:",
                                {
                                    "Ref": "AWS::Partition"
                                },
                                ":ssm:",
                                {
                                    "Ref": "AWS::Region"
                                },
                                ":",
                                {
                                    "Ref": "AWS::AccountId"
                                },
                                ":parameter/test-secret-key"
                            ]
                        ]
                    }
                }
            ],
            "Version": "2012-10-17"
        }
    }));
});

test('Secrets Manager read granted', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const api = new apigateway.RestApi(stack, "TestAPI");
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer.RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret)
    });
    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    // TODO: check for allow to secret
    expectCDK(stack).to(haveResource("AWS::IAM::Policy", {
        "PolicyDocument": {
            "Statement": [
                {
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    "Effect": "Allow",
                    "Resource": {
                        "Fn::Join": [
                            "",
                            [
                                "arn:",
                                {
                                    "Ref": "AWS::Partition"
                                },
                                ":secretsmanager:",
                                {
                                    "Ref": "AWS::Region"
                                },
                                ":",
                                {
                                    "Ref": "AWS::AccountId"
                                },
                                ":secret:test-secret"
                            ]
                        ]
                    }
                }
            ],
            "Version": "2012-10-17"
        }
    }));
});
