import mockedEnv, {RestoreFn} from 'mocked-env';
import {mocked} from 'ts-jest/utils';

import axios from 'axios';

jest.mock('axios');

const mockedGetSecretValue = jest.fn();
const mockedGetParameter = jest.fn();
jest.mock('aws-sdk/clients/secretsmanager', () => jest.fn(() => ({
    getSecretValue: mockedGetSecretValue
})));
jest.mock('aws-sdk/clients/ssm', () => jest.fn(() => ({
    getParameter: mockedGetParameter
})));

const mockedAxios = mocked(axios, true);

let restore: RestoreFn | undefined = undefined;
afterEach(() => {
    if (restore) restore();
});

test('handler allows valid request', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'PLAIN_TEXT',
        SECRET_KEY: 'test-secret-key'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: true,
            score: .9,
            action: 'test-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    const response = await lambda.handler(event);
    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
    expect(response).toEqual({
        principalId: 'user',
        context: {},
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: methodArn
            }]
        }
    });
});

test('handler blocks invalid action', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'PLAIN_TEXT',
        SECRET_KEY: 'test-secret-key'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: true,
            score: .9,
            action: 'blocked-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    const response = await lambda.handler(event);
    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
    expect(response).toEqual({
        principalId: 'user',
        context: {},
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: methodArn
            }]
        }
    });
});

test('handler blocks rejected request', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'PLAIN_TEXT',
        SECRET_KEY: 'test-secret-key'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: false,
            score: .1,
            action: 'test-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    const response = await lambda.handler(event);
    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
    expect(response).toEqual({
        principalId: 'user',
        context: {},
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: methodArn
            }]
        }
    });
});

test('handler caches ssm secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'SSM_PARAMETER',
        SECRET_KEY_PARAMETER_ARN: 'arn:aws:ssm:us-east-1:1234567890:parameter/test-secret-key'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');
    lambda.resetSecret();

    mockedGetParameter.mockReturnValue({
        promise: () => Promise.resolve({
            Parameter: {
                Value: 'test-secret-key'
            }
        })
    });

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: true,
            score: .9,
            action: 'test-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetParameter).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
});

test('handler caches secrets manager secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'SECRETS_MANAGER',
        SECRET_KEY_SECRET_ARN: 'arn:aws:secretsmanager:us-east-1:1234567890:secret:test-secret'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');
    lambda.resetSecret();

    mockedGetSecretValue.mockReturnValue({
        promise: () => Promise.resolve({
            SecretString: 'test-secret-key'
        })
    });

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: true,
            score: .9,
            action: 'test-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetSecretValue).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
});

test('handler parses secrets manager secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_TYPE: 'SECRETS_MANAGER',
        SECRET_KEY_SECRET_ARN: 'arn:aws:secretsmanager:us-east-1:1234567890:secret:test-secret',
        SECRET_KEY_FIELD: 'test_field'
    });

    const lambda = require('../lib/recaptcha-authorizer.function');
    lambda.resetSecret();

    mockedGetSecretValue.mockReturnValue({
        promise: () => Promise.resolve({
            SecretString: JSON.stringify({
                test_field: 'test-secret-key',
                other_field: 'other value'
            })
        })
    });

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            success: true,
            score: .9,
            action: 'test-action',
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com'
        }
    }));

    const methodArn = 'arn:aws:execute-api:us-east-1:1234567890:abcdefghij/prod/GET/test';
    const event = {
        headers: {
            'x-recaptcha-token': 'test-token'
        },
        methodArn,
        requestContext: {
            identity: {
                sourceIp: '1.2.3.4'
            }
        }
    };
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetSecretValue).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: 'test-secret-key',
            response: 'test-token',
            remoteip: '1.2.3.4'
        }
    });
});
