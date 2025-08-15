import { IAMClient, ListAccessKeysCommand, DeleteAccessKeyCommand } from '@aws-sdk/client-iam';

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
      if (error.name === 'UnauthorizedException' || error.name === 'AccessDeniedException') {
        throw new FatalError(`Access denied: ${error.message}`);
      }
      if (error.name === 'ThrottlingException' || error.name === 'ServiceUnavailableException') {
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

export default {
  invoke: async (params, context) => {
    console.log('Starting AWS Revoke User Access Tokens action');

    try {
      validateInputs(params);

      const { userName, region } = params;

      console.log(`Processing user: ${userName} in region: ${region}`);

      if (!context.secrets?.AWS_ACCESS_KEY_ID || !context.secrets?.AWS_SECRET_ACCESS_KEY) {
        throw new FatalError('Missing required AWS credentials in secrets');
      }

      // Create AWS IAM client
      const client = new IAMClient({
        region: region,
        credentials: {
          accessKeyId: context.secrets.AWS_ACCESS_KEY_ID,
          secretAccessKey: context.secrets.AWS_SECRET_ACCESS_KEY
        }
      });

      // Delete all access keys for the user
      const keysDeleted = await deleteAllAccessKeys(client, userName);

      const result = {
        userName,
        keysDeleted,
        revoked: true,
        revokedAt: new Date().toISOString()
      };

      console.log(`Successfully revoked ${keysDeleted} access keys for user: ${userName}`);
      return result;

    } catch (error) {
      console.error(`Error revoking user access tokens: ${error.message}`);

      if (error instanceof RetryableError || error instanceof FatalError) {
        throw error;
      }

      throw new FatalError(`Unexpected error: ${error.message}`);
    }
  },

  error: async (params, _context) => {
    const { error } = params;
    console.error(`Error handler invoked: ${error?.message}`);

    // Re-throw to let framework handle retries
    throw error;
  },

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