/* eslint-disable no-process-env,no-console */
import * as AWS from 'aws-sdk';
import {APIGatewayAuthorizerResult, APIGatewayRequestAuthorizerEvent} from 'aws-lambda';
import axios from 'axios';

/*
 * TODO: capture AWS clients with xray
 * Due to https://github.com/parcel-bundler/parcel/issues/3151 and https://github.com/aws/aws-cdk/issues/7779,
 * the parcel build breaks with aws-xray-sdk
 *
 * import * as xray from 'aws-xray-sdk';
 * const secretsManagerClient = xray.captureAWSClient(new AWS.SecretsManager());
 * const ssmClient = xray.captureAWSClient(new AWS.SSM());
 */
const secretsManagerClient = new AWS.SecretsManager();
const ssmClient = new AWS.SSM();

/**
 * @returns {Promise<string>} the secret key value stored in SSM Parameter Store
 * @param {string} secretKeyParameter The name of the secret key parameter to fetch
 */
const getSsmParameterSecret = async (secretKeyParameter: string): Promise<string> => {
    const parameterResponse = await ssmClient.getParameter({
        Name: secretKeyParameter,
        WithDecryption: true
    }).promise();

    if (!parameterResponse.Parameter?.Value) {
        throw new Error('SSM parameter response missing parameter!');
    }

    return parameterResponse.Parameter.Value;
};

/**
 * @returns {Promise<string>} the secret key value stored in Secrets Manager
 * @param {string} secretKeySecretArn The ARN of the secret key to fetch
 * @param {string | undefined} field An optional field to parse from a JSON secret
 */
const getSecretsManagerSecret = async (secretKeySecretArn: string, field?: string): Promise<string> => {
    const secretResponse = await secretsManagerClient.getSecretValue({
        SecretId: secretKeySecretArn
    }).promise();

    if (!secretResponse.SecretString) {
        throw new Error('Secrets Manager secret response missing secret string!');
    }

    return field ? JSON.parse(secretResponse.SecretString)[field] : secretResponse.SecretString;
};

// eslint-disable-next-line init-declarations
let cachedSecret: string | undefined;

const getSecret = async (): Promise<string> => {
    const {SECRET_KEY_TYPE, SECRET_KEY, SECRET_KEY_PARAMETER, SECRET_KEY_SECRET_ARN, SECRET_KEY_FIELD} = process.env;

    switch (SECRET_KEY_TYPE) {
        case 'PLAIN_TEXT':
            if (!SECRET_KEY) {
                throw new Error('SECRET_KEY was not defined!');
            }

            return SECRET_KEY;
        case 'SSM_PARAMETER':
            if (!SECRET_KEY_PARAMETER) {
                throw new Error('SECRET_KEY_PARAMETER was not defined!');
            }
            if (!cachedSecret) {
                // eslint-disable-next-line require-atomic-updates
                cachedSecret = await getSsmParameterSecret(SECRET_KEY_PARAMETER);
            }

            return cachedSecret;
        case 'SECRETS_MANAGER':
            if (!SECRET_KEY_SECRET_ARN) {
                throw new Error('SECRET_KEY_SECRET_ARN was not defined!');
            }
            if (!cachedSecret) {
                // eslint-disable-next-line require-atomic-updates
                cachedSecret = await getSecretsManagerSecret(SECRET_KEY_SECRET_ARN, SECRET_KEY_FIELD);
            }

            return cachedSecret;
        default:
            throw new Error(`Unsupported secret key type ${SECRET_KEY_TYPE}`);
    }
};

export const resetSecret = (): void => {
    // eslint-disable-next-line no-undefined
    cachedSecret = undefined;
};

/**
 * @returns {APIGatewayAuthorizerResult} that allows or denies this request to the method
 * @param {'Allow' | 'Deny'} effect whether to allow or deny this request
 * @param {string} methodArn the ARN of the method for this request
 */
const generateAuthResponse = (effect: 'Allow' | 'Deny', methodArn: string): APIGatewayAuthorizerResult => ({
    policyDocument: {
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: methodArn
        }],
        Version: '2012-10-17'
    },
    principalId: 'user'
});

const allowedActions = process.env.ALLOWED_ACTIONS ? JSON.parse(process.env.ALLOWED_ACTIONS) : [];

/**
 * Lambda authorizer handler
 * @param {APIGatewayRequestAuthorizerEvent} event - API Gateway Lambda Proxy Input Format
 * @returns {APIGatewayAuthorizerResult} API Gateway Lambda Proxy Output Format
 */
// eslint-disable-next-line max-statements
export const handler = async (event: APIGatewayRequestAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
    const token = event.headers?.['x-recaptcha-token'];
    const {methodArn, requestContext: {identity: {sourceIp}}} = event;

    if (!token) {
        console.log('DENY: header X-reCAPTCHA-Token not found');

        return generateAuthResponse('Deny', methodArn);
    }

    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            remoteip: sourceIp,
            response: token,
            secret: await getSecret()
        }
    });

    if (!response.data.success) {
        console.log(`DENY: score=${response.data.score}; IP: ${sourceIp}; Token: ${token}; ARN: ${methodArn}`);

        return generateAuthResponse('Deny', methodArn);
    }

    if (!allowedActions.includes(response.data.action)) {
        console.log(`DENY: reCAPTCHA action=${response.data.action} not allowed`);

        return generateAuthResponse('Deny', methodArn);
    }

    console.log(`ALLOW: score=${response.data.score}; IP: ${sourceIp}; Token: ${token}; ARN: ${methodArn}`);

    return generateAuthResponse('Allow', methodArn);
};
