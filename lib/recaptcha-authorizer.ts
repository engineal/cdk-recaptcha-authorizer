import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNodeJS from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import {Construct} from 'constructs';
import {SecretKey} from './secret-key';

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
     * The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't
     * remove the log retention policy. To remove the retention policy, set the value to `INFINITE`.
     *
     * @default logs.RetentionDays.INFINITE
     */
    readonly logRetention?: logs.RetentionDays;

    /**
     * Enable AWS X-Ray Tracing for Lambda Function.
     *
     * @default Tracing.Disabled
     */
    readonly tracing?: lambda.Tracing;

}

const MIN_SCORE_THRESHOLD = 0.0;
const MAX_SCORE_THRESHOLD = 1.0;
const DEFAULT_SCORE_THRESHOLD = 0.5;

/**
 * Request-based lambda authorizer that authorizes requests using Google's reCaptcha API
 *
 * @resource AWS::ApiGateway::Authorizer
 */
export class RecaptchaAuthorizer extends apigateway.Authorizer implements apigateway.IAuthorizer {

    private authorizer: apigateway.RequestAuthorizer;

    /**
     * The authorization type of this authorizer.
     */
    readonly authorizationType?: apigateway.AuthorizationType;

    constructor(scope: Construct, id: string, props: RecaptchaAuthorizerProps) {
        super(scope, id);

        const scoreThreshold = props.scoreThreshold ?? DEFAULT_SCORE_THRESHOLD;

        if (scoreThreshold < MIN_SCORE_THRESHOLD || scoreThreshold > MAX_SCORE_THRESHOLD) {
            throw new Error('scoreThreshold must be between 0.0 and 1.0');
        }

        const handler = new lambdaNodeJS.NodejsFunction(this, 'function', {
            bundling: {
                minify: true
            },
            environment: {
                ALLOWED_ACTIONS: JSON.stringify(props.allowedActions),
                SCORE_THRESHOLD: scoreThreshold.toString(),
                SECRET_KEY_TYPE: props.reCaptchaSecretKey.secretKeyType,
                ...props.reCaptchaSecretKey.environment
            },
            logRetention: props.logRetention,
            tracing: props.tracing
        });

        if (props.reCaptchaSecretKey.grantRead) {
            props.reCaptchaSecretKey.grantRead(handler);
        }

        this.authorizer = new apigateway.RequestAuthorizer(this, 'Authorizer', {
            handler,
            identitySources: [apigateway.IdentitySource.header('X-reCAPTCHA-Token')]
        });
        this.authorizationType = this.authorizer.authorizationType;
    }

    /**
     * The authorizer ID.
     * @attribute
     */
    get authorizerId(): string {
        return this.authorizer.authorizerId;
    }

    /**
     * Attaches this authorizer to a specific REST API.
     * @internal
     * @returns {void}
     * @param {RestApi} restApi the rest API to attach this authorizer to
     */
    public _attachToApi(restApi: apigateway.RestApi): void {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // eslint-disable-next-line no-underscore-dangle
        this.authorizer._attachToApi(restApi);
    }

}
