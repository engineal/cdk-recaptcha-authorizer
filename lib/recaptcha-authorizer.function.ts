import axios from 'axios';
import * as SecretsManager from 'aws-sdk/clients/secretsmanager';
import * as SSM from 'aws-sdk/clients/ssm';

/*
 * TODO: capture AWS clients with xray
 * Due to https://github.com/parcel-bundler/parcel/issues/3151 and https://github.com/aws/aws-cdk/issues/7779,
 * the parcel build breaks with aws-xray-sdk
 */
//import * as xray from 'aws-xray-sdk';
//const secretsManagerClient = xray.captureAWSClient(new SecretsManager());
//const ssmClient = xray.captureAWSClient(new SSM());
const secretsManagerClient = new SecretsManager();
const ssmClient = new SSM();

const allowedActions = JSON.parse(process.env.ALLOWED_ACTIONS!);

/**
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 */
export const handler = async (event: any) => {
    const token = event.headers['x-recaptcha-token'];
    const sourceIp = event.requestContext.identity.sourceIp;
    const methodArn = event.methodArn;

    let response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
        params: {
            secret: await getSecret(),
            response: token,
            remoteip: sourceIp
        }
    });

    if (!response.data.success) {
        console.log(`DENY: score=${response.data.score}; IP: ${sourceIp}; Token: ${token}; ARN: ${methodArn}`);
        return generateAuthResponse('user', 'Deny', methodArn);
    }

    if (!allowedActions.includes(response.data.action)) {
        console.log(`DENY: reCAPTCHA action=${response.data.action} not allowed`);
        return generateAuthResponse('user', 'Deny', methodArn);
    }

    console.log(`ALLOW: score=${response.data.score}; IP: ${sourceIp}; Token: ${token}; ARN: ${methodArn}`);
    return generateAuthResponse('user', 'Allow', methodArn);
};

let cachedSecret: string | undefined = undefined;

async function getSecret(): Promise<string> {
    switch (process.env.SECRET_KEY_TYPE) {
        case 'PLAIN_TEXT':
            return process.env.SECRET_KEY!;
        case 'SSM_PARAMETER':
            if (!cachedSecret) cachedSecret = await getSsmParameterSecret(process.env.SECRET_KEY_PARAMETER_ARN!);
            return cachedSecret;
        case 'SECRETS_MANAGER':
            if (!cachedSecret) cachedSecret = await getSecretsManagerSecret(process.env.SECRET_KEY_SECRET_ARN!, process.env.SECRET_KEY_FIELD);
            return cachedSecret;
        default:
            throw new Error(`Unsupported secret key type ${process.env.SECRET_KEY_TYPE}`);
    }
}

export const resetSecret = () => {
    cachedSecret = undefined;
};

async function getSsmParameterSecret(secretKeyParameterArn: string): Promise<string> {
    const parameterResponse = await ssmClient.getParameter({
        Name: secretKeyParameterArn,
        WithDecryption: true
    }).promise();
    if (parameterResponse.Parameter?.Value) {
        return parameterResponse.Parameter.Value;
    } else {
        throw new Error("SSM parameter response missing parameter!");
    }
}

async function getSecretsManagerSecret(secretKeySecretArn: string, field?: string): Promise<string> {
    const secretResponse = await secretsManagerClient.getSecretValue({
        SecretId: secretKeySecretArn
    }).promise();
    if (secretResponse.SecretString) {
        if (field) {
            const secret = JSON.parse(secretResponse.SecretString);
            return secret[field];
        } else {
            return secretResponse.SecretString;
        }
    } else {
        throw new Error("Secrets Manager secret response missing secret string!");
    }
}

function generateAuthResponse(principalId: string, effect: string, methodArn: string) {
    // If you need to provide additional information to your integration
    // endpoint (e.g. your Lambda Function), you can add it to `context`
    const context = {};
    const policyDocument = generatePolicyDocument(effect, methodArn);

    return {
        principalId,
        context,
        policyDocument
    };
}

function generatePolicyDocument(effect: string, methodArn: string) {
    if (!effect ?? !methodArn) return null;

    return {
        Version: '2012-10-17',
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: methodArn
        }]
    };
}
