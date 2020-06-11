import {Grant, IGrantable} from "@aws-cdk/aws-iam";
import {ISecret} from "@aws-cdk/aws-secretsmanager";
import {IParameter} from "@aws-cdk/aws-ssm";

/**
 * A reCaptcha secret key.
 */
export abstract class SecretKey {
    /**
     * @returns a secret key from a string in plain text.
     * @param secretKey The secret key in plain text.
     */
    public static fromPlainText(secretKey: string): SecretKey {
        return {
            secretKeyType: 'PLAIN_TEXT',
            environment: {
                SECRET_KEY: secretKey
            }
        };
    }

    /**
     * @returns a secret key from a parameter stored in AWS Systems Manager Parameter Store.
     * @param secretKeyParameter The parameter in which the secret key is stored.
     */
    public static fromSsmParameter(secretKeyParameter: IParameter): SecretKey {
        return {
            secretKeyType: 'SSM_PARAMETER',
            environment: {
                SECRET_KEY_PARAMETER: secretKeyParameter.parameterName
            },
            grantRead: grantee => secretKeyParameter.grantRead(grantee)
        };
    }

    /**
     * @returns a secret key from a secret stored in AWS Secrets Manager.
     * @param secretKeySecret The secret in which the secret key is stored.
     * @param field the name of the field with the value that you want to use as the secret key.
     * Only values in JSON format are supported. If you do not specify a JSON field, then the full
     * content of the secret is used.
     */
    public static fromSecretsManager(secretKeySecret: ISecret, field?: string): SecretKey {
        return {
            secretKeyType: 'SECRETS_MANAGER',
            environment: {
                SECRET_KEY_SECRET_ARN: secretKeySecret.secretArn,
                SECRET_KEY_FIELD: field
            },
            grantRead: grantee => secretKeySecret.grantRead(grantee)
        };
    }

    /**
     * The type of secret key
     */
    abstract readonly secretKeyType: string;

    /**
     * Key-value pairs that should be added as environment variables to the Lambda
     */
    abstract readonly environment: { [key: string]: string | undefined }

    /**
     * Grants reading the secret to a principal
     */
    abstract grantRead?(grantee: IGrantable): Grant;
}
