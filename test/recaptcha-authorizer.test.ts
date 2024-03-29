/* eslint-disable max-lines */
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cdk from 'aws-cdk-lib/core';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import {RecaptchaAuthorizer, SecretKey} from '../lib';
import {Template} from 'aws-cdk-lib/assertions';

test('Lambda Function Created with plain text secret key', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret')
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0.5',
                SECRET_KEY: 'secret',
                SECRET_KEY_TYPE: 'PLAIN_TEXT'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

test('Lambda Function Created with ssm secret key', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    const secretKeyParameter = ssm.StringParameter.fromStringParameterName(stack, 'TestParameter', 'test-secret-key');
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSsmParameter(secretKeyParameter)
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0.5',
                SECRET_KEY_PARAMETER: 'test-secret-key',
                SECRET_KEY_TYPE: 'SSM_PARAMETER'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

// eslint-disable-next-line max-lines-per-function
test('Lambda Function Created with secrets manager secret key', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretPartialArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret)
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0.5',
                SECRET_KEY_SECRET_ARN: {
                    'Fn::Join': [
                        '',
                        [
                            'arn:',
                            {
                                Ref: 'AWS::Partition'
                            },
                            ':secretsmanager:',
                            {
                                Ref: 'AWS::Region'
                            },
                            ':',
                            {
                                Ref: 'AWS::AccountId'
                            },
                            ':secret:test-secret'
                        ]
                    ]
                },
                SECRET_KEY_TYPE: 'SECRETS_MANAGER'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

// eslint-disable-next-line max-lines-per-function
test('Lambda Function Created with secrets manager and json field', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretPartialArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret, 'test-field')
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0.5',
                SECRET_KEY_FIELD: 'test-field',
                SECRET_KEY_SECRET_ARN: {
                    'Fn::Join': [
                        '',
                        [
                            'arn:',
                            {
                                Ref: 'AWS::Partition'
                            },
                            ':secretsmanager:',
                            {
                                Ref: 'AWS::Region'
                            },
                            ':',
                            {
                                Ref: 'AWS::AccountId'
                            },
                            ':secret:test-secret'
                        ]
                    ]
                },
                SECRET_KEY_TYPE: 'SECRETS_MANAGER'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

// eslint-disable-next-line max-lines-per-function
test('Request Authorizer Created', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret')
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::ApiGateway::Authorizer', {
        AuthorizerUri: {
            'Fn::Join': [
                '',
                [
                    'arn:',
                    {
                        'Fn::Select': [
                            // eslint-disable-next-line no-magic-numbers
                            1,
                            {
                                'Fn::Split': [
                                    ':',
                                    {
                                        'Fn::GetAtt': [
                                            'TestAuthorizerfunction3F10EDDB',
                                            'Arn'
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    ':apigateway:',
                    {
                        'Fn::Select': [
                            // eslint-disable-next-line no-magic-numbers
                            3,
                            {
                                'Fn::Split': [
                                    ':',
                                    {
                                        'Fn::GetAtt': [
                                            'TestAuthorizerfunction3F10EDDB',
                                            'Arn'
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    ':lambda:path/2015-03-31/functions/',
                    {
                        'Fn::GetAtt': [
                            'TestAuthorizerfunction3F10EDDB',
                            'Arn'
                        ]
                    },
                    '/invocations'
                ]
            ]
        },
        IdentitySource: 'method.request.header.X-reCAPTCHA-Token',
        Type: 'REQUEST'
    });

    template.hasResourceProperties('AWS::ApiGateway::Method', {
        AuthorizationType: 'CUSTOM',
        AuthorizerId: {
            Ref: 'TestAuthorizer64D89012'
        }
    });
});

// eslint-disable-next-line max-lines-per-function
test('SSM parameter read granted', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    const secretKeyParameter = ssm.StringParameter.fromStringParameterName(stack, 'TestParameter', 'test-secret-key');
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSsmParameter(secretKeyParameter)
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
            Statement: [
                {
                    Action: [
                        'ssm:DescribeParameters',
                        'ssm:GetParameters',
                        'ssm:GetParameter',
                        'ssm:GetParameterHistory'
                    ],
                    Effect: 'Allow',
                    Resource: {
                        'Fn::Join': [
                            '',
                            [
                                'arn:',
                                {
                                    Ref: 'AWS::Partition'
                                },
                                ':ssm:',
                                {
                                    Ref: 'AWS::Region'
                                },
                                ':',
                                {
                                    Ref: 'AWS::AccountId'
                                },
                                ':parameter/test-secret-key'
                            ]
                        ]
                    }
                }
            ],
            Version: '2012-10-17'
        }
    });
});

// eslint-disable-next-line max-lines-per-function
test('Secrets Manager read granted', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');
    const secretKeySecret = secretsmanager.Secret.fromSecretAttributes(stack, 'TestSecret', {
        secretPartialArn: `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:test-secret`
    });
    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromSecretsManager(secretKeySecret)
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });
    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
            Statement: [
                {
                    Action: [
                        'secretsmanager:GetSecretValue',
                        'secretsmanager:DescribeSecret'
                    ],
                    Effect: 'Allow',
                    Resource: {
                        'Fn::Join': [
                            '',
                            [
                                'arn:',
                                {
                                    Ref: 'AWS::Partition'
                                },
                                ':secretsmanager:',
                                {
                                    Ref: 'AWS::Region'
                                },
                                ':',
                                {
                                    Ref: 'AWS::AccountId'
                                },
                                ':secret:test-secret-??????'
                            ]
                        ]
                    }
                }
            ],
            Version: '2012-10-17'
        }
    });
});

test('Score threshold -3 out of bounds', () => {
    const stack = new cdk.Stack();

    // THEN
    expect(() => new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret'),
        scoreThreshold: -3
    })).toThrowError('scoreThreshold must be between 0.0 and 1.0');
});

test('Score threshold 2 out of bounds', () => {
    const stack = new cdk.Stack();

    // THEN
    expect(() => new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret'),
        scoreThreshold: 2
    })).toThrowError('scoreThreshold must be between 0.0 and 1.0');
});

test('Score threshold 0.0 within bounds', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');

    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret'),
        scoreThreshold: 0.0
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });

    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0',
                SECRET_KEY: 'secret',
                SECRET_KEY_TYPE: 'PLAIN_TEXT'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

test('Score threshold 1.0 within bounds', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');

    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret'),
        scoreThreshold: 1.0
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });

    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '1',
                SECRET_KEY: 'secret',
                SECRET_KEY_TYPE: 'PLAIN_TEXT'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});

test('Score threshold 0.7 within bounds', () => {
    const stack = new cdk.Stack();
    const api = new apigateway.RestApi(stack, 'TestAPI');

    // WHEN
    const authorizer = new RecaptchaAuthorizer(stack, 'TestAuthorizer', {
        allowedActions: ['test-action'],
        reCaptchaSecretKey: SecretKey.fromPlainText('secret'),
        scoreThreshold: 0.7
    });

    api.root.addMethod('GET', new apigateway.MockIntegration(), {
        authorizer
    });

    // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
            Variables: {
                ALLOWED_ACTIONS: '["test-action"]',
                AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1',
                SCORE_THRESHOLD: '0.7',
                SECRET_KEY: 'secret',
                SECRET_KEY_TYPE: 'PLAIN_TEXT'
            }
        },
        Handler: 'index.handler',
        Runtime: {
            'Fn::FindInMap': ['DefaultCrNodeVersionMap', {Ref: 'AWS::Region'}, 'value']
        }
    });
});
