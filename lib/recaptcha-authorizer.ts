import {Construct} from '@aws-cdk/core';
import {IdentitySource, RequestAuthorizer} from "@aws-cdk/aws-apigateway";
import {NodejsFunction} from "@aws-cdk/aws-lambda-nodejs";
import {SecretKey} from "./secret-key";

export interface RecaptchaAuthorizerProps {
    /**
     * The actions to be allowed by this authorizer
     */
    readonly allowedActions: string[]
    /**
     * The secret key
     */
    readonly reCaptchaSecretKey: SecretKey
}

/**
 * Request-based lambda authorizer that authorizes requests using Google's reCaptcha API
 *
 * @resource AWS::ApiGateway::Authorizer
 */
export class RecaptchaAuthorizer extends RequestAuthorizer {
    constructor(scope: Construct, id: string, props: RecaptchaAuthorizerProps) {
        const handler = new NodejsFunction(scope, 'function', {
            environment: {
                ALLOWED_ACTIONS: JSON.stringify(props.allowedActions),
                SECRET_KEY_TYPE: props.reCaptchaSecretKey.secretKeyType,
                ...props.reCaptchaSecretKey.environment
            }
        });

        if (props.reCaptchaSecretKey.grantRead) props.reCaptchaSecretKey.grantRead(handler);

        super(scope, id, {
            handler,
            identitySources: [IdentitySource.header('X-reCAPTCHA-Token')]
        });
    }
}
