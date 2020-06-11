import {Construct} from '@aws-cdk/core';
import {
    AuthorizationType,
    Authorizer,
    IAuthorizer,
    IdentitySource,
    RequestAuthorizer,
    RestApi
} from "@aws-cdk/aws-apigateway";
import {Tracing} from "@aws-cdk/aws-lambda";
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
    /**
     * Enable AWS X-Ray Tracing for Lambda Function.
     *
     * @default Tracing.Disabled
     */
    readonly tracing?: Tracing;
}

/**
 * Request-based lambda authorizer that authorizes requests using Google's reCaptcha API
 *
 * @resource AWS::ApiGateway::Authorizer
 */
export class RecaptchaAuthorizer extends Authorizer implements IAuthorizer {

    private authorizer: RequestAuthorizer;

    constructor(scope: Construct, id: string, props: RecaptchaAuthorizerProps) {
        super(scope, id);

        const handler = new NodejsFunction(this, 'function', {
            environment: {
                ALLOWED_ACTIONS: JSON.stringify(props.allowedActions),
                SECRET_KEY_TYPE: props.reCaptchaSecretKey.secretKeyType,
                ...props.reCaptchaSecretKey.environment
            },
            tracing: props.tracing
        });
        if (props.reCaptchaSecretKey.grantRead) props.reCaptchaSecretKey.grantRead(handler);

        this.authorizer = new RequestAuthorizer(this, 'Authorizer', {
            handler,
            identitySources: [IdentitySource.header('X-reCAPTCHA-Token')]
        });
    }

    /**
     * The authorizer ID.
     * @attribute
     */
    get authorizerId() {
        return this.authorizer.authorizerId;
    }

    /**
     * The authorization type of this authorizer.
     */
    get authorizationType(): AuthorizationType | undefined {
        return this.authorizer.authorizationType;
    }

    /**
     * The authorization type of this authorizer.
     */
    set authorizationType(authorizationType: AuthorizationType | undefined) {}

    /**
     * Attaches this authorizer to a specific REST API.
     * @internal
     */
    public _attachToApi(restApi: RestApi) {
        // @ts-ignore
        this.authorizer._attachToApi(restApi);
    }
}
