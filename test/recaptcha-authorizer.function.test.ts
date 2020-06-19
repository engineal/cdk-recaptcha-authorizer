/* eslint-disable no-magic-numbers */
import mockedEnv, {RestoreFn} from 'mocked-env';
import axios from 'axios';
import {mocked} from 'ts-jest/utils';

jest.mock('axios');
const mockedAxios = mocked(axios, true);

const mockedGetSecretValue = jest.fn();
const mockedGetParameter = jest.fn();

jest.mock('aws-sdk', () => ({
    SSM: jest.fn(() => ({
        getParameter: mockedGetParameter
    })),
    SecretsManager: jest.fn(() => ({
        getSecretValue: mockedGetSecretValue
    }))
}));

/*
 * TODO: add back when aws-xray-sdk is enabled
 *
 * jest.mock('aws-xray-sdk', () => ({
 *     captureAWSClient: (client: any) => client
 * }));
 */

// eslint-disable-next-line init-declarations
let restore: RestoreFn | undefined;

afterEach(() => {
    if (restore) {
        restore();
    }
});

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

test('handler allows valid request', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY: 'test-secret-key',
        SECRET_KEY_TYPE: 'PLAIN_TEXT'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.9,
            success: true
        }
    }));
    // WHEN
    const response = await lambda.handler(event);

    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
    expect(response).toEqual({
        policyDocument: {
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: methodArn
            }],
            Version: '2012-10-17'
        },
        principalId: 'user'
    });
});

test('handler blocks rejected request', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY: 'test-secret-key',
        SECRET_KEY_TYPE: 'PLAIN_TEXT'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.1,
            success: false
        }
    }));
    // WHEN
    const response = await lambda.handler(event);

    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
    expect(response).toEqual({
        policyDocument: {
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: methodArn
            }],
            Version: '2012-10-17'
        },
        principalId: 'user'
    });
});

test('handler blocks score below threshold', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY: 'test-secret-key',
        SECRET_KEY_TYPE: 'PLAIN_TEXT'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.1,
            success: true
        }
    }));
    // WHEN
    const response = await lambda.handler(event);

    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
    expect(response).toEqual({
        policyDocument: {
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: methodArn
            }],
            Version: '2012-10-17'
        },
        principalId: 'user'
    });
});

test('handler blocks invalid action', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY: 'test-secret-key',
        SECRET_KEY_TYPE: 'PLAIN_TEXT'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'blocked-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.9,
            success: true
        }
    }));
    // WHEN
    const response = await lambda.handler(event);

    // THEN
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
    expect(response).toEqual({
        policyDocument: {
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: methodArn
            }],
            Version: '2012-10-17'
        },
        principalId: 'user'
    });
});

test('handler caches ssm secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_PARAMETER: 'test-secret-key',
        SECRET_KEY_TYPE: 'SSM_PARAMETER'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
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
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.9,
            success: true
        }
    }));
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetParameter).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
});

test('handler caches secrets manager secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_SECRET_ARN: 'arn:aws:secretsmanager:us-east-1:1234567890:secret:test-secret',
        SECRET_KEY_TYPE: 'SECRETS_MANAGER'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    lambda.resetSecret();

    mockedGetSecretValue.mockReturnValue({
        promise: () => Promise.resolve({
            SecretString: 'test-secret-key'
        })
    });

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.9,
            success: true
        }
    }));
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetSecretValue).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
});

test('handler parses secrets manager secret', async () => {
    restore = mockedEnv({
        ALLOWED_ACTIONS: '["test-action"]',
        SECRET_KEY_FIELD: 'testField',
        SECRET_KEY_SECRET_ARN: 'arn:aws:secretsmanager:us-east-1:1234567890:secret:test-secret',
        SECRET_KEY_TYPE: 'SECRETS_MANAGER'
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const lambda = require('../lib/recaptcha-authorizer.function');

    lambda.resetSecret();

    mockedGetSecretValue.mockReturnValue({
        promise: () => Promise.resolve({
            SecretString: JSON.stringify({
                otherField: 'other value',
                testField: 'test-secret-key'
            })
        })
    });

    mockedAxios.post.mockReturnValue(Promise.resolve({
        data: {
            action: 'test-action',
            // eslint-disable-next-line camelcase
            challenge_ts: new Date().toISOString(),
            hostname: 'example.com',
            score: 0.9,
            success: true
        }
    }));
    // WHEN
    await lambda.handler(event);
    await lambda.handler(event);
    // THEN
    expect(mockedGetSecretValue).toBeCalledTimes(1);
    expect(mockedAxios.post).toBeCalledWith('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: '1.2.3.4',
            response: 'test-token',
            secret: 'test-secret-key'
        }
    });
});
