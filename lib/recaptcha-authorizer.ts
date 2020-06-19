import {
    AuthorizationType,
    Authorizer,
    IAuthorizer,
    IdentitySource,
    RequestAuthorizer,
    RestApi
} from '@aws-cdk/aws-apigateway';
import {Construct} from '@aws-cdk/core';
import {NodejsFunction} from '@aws-cdk/aws-lambda-nodejs';
import {SecretKey} from './secret-key';
import {Tracing} from '@aws-cdk/aws-lambda';

export interface RecaptchaAuthorizerProps {

    /**
     * The minimum score threshold to allow by this authorizer
     *
     * @default 0.5
     */
    readonly scoreThreshold?: number

    /**
     * The actions to be allowed by this authorizer
     */
    readonly allowedActions: string[]

    /**
     * The reCaptcha API secret key
     */
    readonly reCaptchaSecretKey: SecretKey

    /**
     * Enable AWS X-Ray Tracing for Lambda Function.
     *
     * @default Tracing.Disabled
     */
    readonly tracing?: Tracing;

}

const MIN_SCORE_THRESHOLD = 0.0;
const MAX_SCORE_THRESHOLD = 1.0;
const DEFAULT_SCORE_THRESHOLD = 0.5;

/**
 * Request-based lambda authorizer that authorizes requests using Google's reCaptcha API
 *
 * @resource AWS::ApiGateway::Authorizer
 */
export class RecaptchaAuthorizer extends Authorizer implements IAuthorizer {

    private authorizer: RequestAuthorizer;

    constructor(scope: Construct, id: string, props: RecaptchaAuthorizerProps) {
        super(scope, id);

        const scoreThreshold = props.scoreThreshold ?? DEFAULT_SCORE_THRESHOLD;

        if (scoreThreshold < MIN_SCORE_THRESHOLD || scoreThreshold > MAX_SCORE_THRESHOLD) {
            throw new Error('scoreThreshold must be between 0.0 and 1.0');
        }

        const handler = new NodejsFunction(this, 'function', {
            environment: {
                ALLOWED_ACTIONS: JSON.stringify(props.allowedActions),
                SCORE_THRESHOLD: scoreThreshold.toString(),
                SECRET_KEY_TYPE: props.reCaptchaSecretKey.secretKeyType,
                ...props.reCaptchaSecretKey.environment
            },
            minify: true,
            tracing: props.tracing
        });

        if (props.reCaptchaSecretKey.grantRead) {
            props.reCaptchaSecretKey.grantRead(handler);
        }

        this.authorizer = new RequestAuthorizer(this, 'Authorizer', {
            handler,
            identitySources: [IdentitySource.header('X-reCAPTCHA-Token')]
        });
    }

    /**
     * The authorizer ID.
     * @attribute
     */
    get authorizerId(): string {
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
    // eslint-disable-next-line class-methods-use-this
    set authorizationType(authorizationType: AuthorizationType | undefined) {
        // This is readonly, do nothing
    }

    /**
     * Attaches this authorizer to a specific REST API.
     * @internal
     * @returns {void}
     * @param {RestApi} restApi the rest API to attach this authorizer to
     */
    public _attachToApi(restApi: RestApi): void {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // eslint-disable-next-line no-underscore-dangle
        this.authorizer._attachToApi(restApi);
    }

}
