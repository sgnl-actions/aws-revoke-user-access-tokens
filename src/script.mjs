import { IAMClient, ListAccessKeysCommand, DeleteAccessKeyCommand } from '@aws-sdk/client-iam';
import { getAwsCredentials } from './auth.mjs';
import { randomUUID } from 'node:crypto';

class RetryableError extends Error {
  constructor(message) {
    super(message);
    this.retryable = true;
  }
}

class FatalError extends Error {
  constructor(message) {
    super(message);
    this.retryable = false;
  }
}

/**
 * Delete all IAM access keys for a given user.
 * @param {IAMClient} client - Configured AWS IAM client instance.
 * @param {string} userName - IAM user name whose keys should be revoked.
 * @returns {Promise<number>} Total number of keys deleted.
 */
async function deleteAllAccessKeys(client, userName) {
  let keysDeleted = 0;
  let marker = undefined;

  do {
    // List access keys for the user
    const listCommand = new ListAccessKeysCommand({
      UserName: userName,
      Marker: marker
    });

    let listResponse;
    try {
      listResponse = await client.send(listCommand);
    } catch (error) {
      if (error.name === 'NoSuchEntityException') {
        throw new FatalError(`User not found: ${userName}`);
      }
      if (error.name === 'UnauthorizedException' || error.name === 'AccessDeniedException' || error.name === 'AccessDenied') {
        throw new FatalError(`Access denied: ${error.message}`);
      }
      if (error.name === 'ThrottlingException' || error.name === 'ServiceUnavailableException' || error.name === 'Throttling') {
        throw new RetryableError(`AWS service temporarily unavailable: ${error.message}`);
      }
      throw new FatalError(`Failed to list access keys: ${error.message}`);
    }

    // Delete each access key
    for (const key of listResponse.AccessKeyMetadata || []) {
      const deleteCommand = new DeleteAccessKeyCommand({
        UserName: userName,
        AccessKeyId: key.AccessKeyId
      });

      try {
        await client.send(deleteCommand);
        keysDeleted++;
        console.log(`Deleted access key: ${key.AccessKeyId}`);
      } catch (error) {
        if (error.name === 'NoSuchEntityException') {
          // Key already deleted, continue
          console.log(`Access key already deleted: ${key.AccessKeyId}`);
          continue;
        }
        if (error.name === 'ThrottlingException' || error.name === 'ServiceUnavailableException') {
          throw new RetryableError(`AWS service temporarily unavailable: ${error.message}`);
        }
        throw new FatalError(`Failed to delete access key ${key.AccessKeyId}: ${error.message}`);
      }
    }

    // Check if there are more results
    marker = listResponse.IsTruncated ? listResponse.Marker : undefined;
  } while (marker);

  return keysDeleted;
}

function validateInputs(params) {
  if (!params.userName || typeof params.userName !== 'string' || params.userName.trim() === '') {
    throw new FatalError('Invalid or missing userName parameter');
  }

  if (!params.region || typeof params.region !== 'string' || params.region.trim() === '') {
    throw new FatalError('Invalid or missing region parameter');
  }
}

function hasBasicAuth(context) {
  return Boolean(context.secrets?.BASIC_USERNAME && context.secrets?.BASIC_PASSWORD);
}

function hasOAuth2ClientCredentials(context) {
  return Boolean(
    context.environment?.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID &&
      context.environment?.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL &&
      context.secrets?.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
  );
}

function hasAwsAssumeRoleWebIdentityConfig(context) {
  return Boolean(
    context.environment?.AWS_ASSUME_ROLE_WEB_IDENTITY_REGION &&
    context.environment?.AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN
  );
}

function buildAwsCredentialsParams(context) {
  if (hasBasicAuth(context)) {
    return {
      basic: {
        username:  context.secrets.BASIC_USERNAME,
        password: context.secrets.BASIC_PASSWORD
      }
    };
  }

  if (hasOAuth2ClientCredentials(context)) {
    if (!hasAwsAssumeRoleWebIdentityConfig(context)) {
      throw new FatalError('OAuth2ClientCredentials missing required AwsAssumeRoleWebIdentity configuration');
    }

    return {
      clientCredentials: {
        clientId: context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID,
        clientSecret: context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET,
        tokenUrl: context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL,
        scope: context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE,
        audience: context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE,
        authStyle: context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE,
        awsConfig: {
          region: context.environment.AWS_ASSUME_ROLE_WEB_IDENTITY_REGION,
          roleArn: context.environment.AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN,
          sessionName: context.environment.AWS_ASSUME_ROLE_WEB_IDENTITY_SESSION_NAME || `sgnl-action-${randomUUID()}`,
          sessionDuration: context.environment.AWS_ASSUME_ROLE_WEB_IDENTITY_SESSION_DURATION_SECONDS
        }
      }
    };
  }

  throw new FatalError('unsupported auth type: expected Basic or OAuth2ClientCredentials with AwsAssumeRoleWebIdentity');
}

export default {
  /**
   * Main execution handler - revokes AWS IAM user access tokens
   * @param {Object} params - Job input parameters
   * @param {string} params.userName - IAM user name
   * @param {string} params.region - AWS region
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.secrets.BASIC_USERNAME - AWS Access Key ID
   * @param {string} context.secrets.BASIC_PASSWORD - AWS Secret Access Key
   * @returns {Object} Revocation results
   */
  invoke: async (params, context) => {
    console.log('Starting AWS Revoke User Access Tokens action');

    try {
      validateInputs(params);

      const { userName, region } = params;

      console.log(`Processing user: ${userName} in region: ${region}`);

      const awsCredentailsParams = buildAwsCredentialsParams(context);

      // Create AWS IAM client
      const client = new IAMClient({
        region: region,
        credentials: await getAwsCredentials(awsCredentailsParams)
      });

      // Delete all access keys for the user
      const keysDeleted = await deleteAllAccessKeys(client, userName);

      console.log(`Successfully revoked ${keysDeleted} access keys for user: ${userName}`);
      return {
        userName,
        keysDeleted,
        revoked: true,
        revokedAt: new Date().toISOString()
      };

    } catch (error) {
      console.error(`Error revoking user access tokens: ${error.message}`);

      if (error instanceof RetryableError || error instanceof FatalError) {
        throw error;
      }

      throw new FatalError(`Unexpected error: ${error.message}`);
    }
  },

  /**
   * Error recovery handler - handles retryable errors
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error } = params;
    console.error(`Error handler invoked: ${error?.message}`);

    // Re-throw to let framework handle retries
    throw error;
  },

  /**
   * Graceful shutdown handler - performs cleanup
   * @param {Object} params - Original params plus halt reason
   * @param {Object} context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason, userName } = params;
    console.log(`Job is being halted (${reason})`);

    return {
      userName: userName || 'unknown',
      reason: reason || 'unknown',
      haltedAt: new Date().toISOString(),
      cleanupCompleted: true
    };
  }
};