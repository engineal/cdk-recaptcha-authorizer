import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';

/**
 * A reCaptcha secret key.
 */
export abstract class SecretKey {

    /**
     * @returns {SecretKey} a secret key from a string in plain text.
     * @param {string} secretKey The secret key in plain text.
     */
    public static fromPlainText(secretKey: string): SecretKey {
        return {
            environment: {
                SECRET_KEY: secretKey
            },
            secretKeyType: 'PLAIN_TEXT'
        };
    }

    /**
     * @returns {SecretKey} a secret key from a parameter stored in AWS Systems Manager Parameter Store.
     * @param {ssm.IParameter} secretKeyParameter The parameter in which the secret key is stored.
     */
    public static fromSsmParameter(secretKeyParameter: ssm.IParameter): SecretKey {
        return {
            environment: {
                SECRET_KEY_PARAMETER: secretKeyParameter.parameterName
            },
            grantRead: grantee => secretKeyParameter.grantRead(grantee),
            secretKeyType: 'SSM_PARAMETER'
        };
    }

    /**
     * @returns {SecretKey} a secret key from a secret stored in AWS Secrets Manager.
     * @param {secretsmanager.ISecret} secretKeySecret The secret in which the secret key is stored.
     * @param {string} field the name of the field with the value that you want to use as the secret key.
     * Only values in JSON format are supported. If you do not specify a JSON field, then the full
     * content of the secret is used.
     */
    public static fromSecretsManager(secretKeySecret: secretsmanager.ISecret, field?: string): SecretKey {
        const environment: { [key: string]: string } = {
            SECRET_KEY_SECRET_ARN: secretKeySecret.secretArn
        };

        if (field) {
            environment.SECRET_KEY_FIELD = field;
        }

        return {
            environment,
            grantRead: grantee => secretKeySecret.grantRead(grantee),
            secretKeyType: 'SECRETS_MANAGER'
        };
    }

    /**
     * The type of secret key
     */
    abstract readonly secretKeyType: string;

    /**
     * Key-value pairs that should be added as environment variables to the Lambda
     */
    abstract readonly environment: { [key: string]: string }

    /**
     * Grants reading the secret to a principal
     */
    abstract grantRead?(grantee: iam.IGrantable): iam.Grant;

}
