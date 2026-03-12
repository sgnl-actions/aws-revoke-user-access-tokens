import script from '../src/script.mjs';

describe('AWS Revoke User Access Tokens Script', () => {
  const mockContext = {
    env: {
      ENVIRONMENT: 'test'
    },
    secrets: {
      BASIC_USERNAME: 'test-access-key',
      BASIC_PASSWORD: 'test-secret-key'
    },
    outputs: {}
  };

  beforeEach(() => {
    // Mock console to avoid noise in tests
    global.console.log = () => {};
    global.console.error = () => {};
  });

  describe('invoke handler', () => {
    test('should throw error for missing userName', async () => {
      const params = {
        region: 'us-east-1'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'Invalid or missing userName parameter'
      );
    });

    test('should throw error for missing region', async () => {
      const params = {
        userName: 'TestUser'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'Invalid or missing region parameter'
      );
    });

    test('should throw error for missing AWS credentials', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextWithoutCreds = {
        ...mockContext,
        secrets: {}
      };

      await expect(script.invoke(params, contextWithoutCreds)).rejects.toThrow(
        'unsupported auth type: expected Basic or OAuth2ClientCredentials with AwsAssumeRoleWebIdentity'
      );
    });

    test('should validate empty userName', async () => {
      const params = {
        userName: '   ',
        region: 'us-east-1'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'Invalid or missing userName parameter'
      );
    });

    // Note: Testing actual AWS SDK calls would require mocking the SDK
    // or integration tests with real AWS credentials
  });

  describe('AWS AssumeRoleWithWebIdentity authentication validation', () => {
    test('should throw error for OAuth2 without AWS AssumeRole config - missing region', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingAwsRegion = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
          OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://auth.example.com/token',
          AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN:
            'arn:aws:iam::123456789012:role/TestRole'
        },
        secrets: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret'
        },
        outputs: {}
      };

      await expect(
        script.invoke(params, contextMissingAwsRegion)
      ).rejects.toThrow(
        'OAuth2ClientCredentials missing required AwsAssumeRoleWebIdentity configuration'
      );
    });

    test('should throw error for OAuth2 without AWS AssumeRole config - missing role ARN', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingRoleArn = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
          OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://auth.example.com/token',
          AWS_ASSUME_ROLE_WEB_IDENTITY_REGION: 'us-west-2'
        },
        secrets: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret'
        },
        outputs: {}
      };

      await expect(script.invoke(params, contextMissingRoleArn)).rejects.toThrow(
        'OAuth2ClientCredentials missing required AwsAssumeRoleWebIdentity configuration'
      );
    });

    test('should throw error for OAuth2 without AWS AssumeRole config - both missing', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingBoth = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
          OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://auth.example.com/token'
        },
        secrets: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret'
        },
        outputs: {}
      };

      await expect(script.invoke(params, contextMissingBoth)).rejects.toThrow(
        'OAuth2ClientCredentials missing required AwsAssumeRoleWebIdentity configuration'
      );
    });

    test('should throw error for missing OAuth2 client ID', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingClientId = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://auth.example.com/token',
          AWS_ASSUME_ROLE_WEB_IDENTITY_REGION: 'us-west-2',
          AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN:
            'arn:aws:iam::123456789012:role/TestRole'
        },
        secrets: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret'
        },
        outputs: {}
      };

      await expect(script.invoke(params, contextMissingClientId)).rejects.toThrow(
        'unsupported auth type: expected Basic or OAuth2ClientCredentials with AwsAssumeRoleWebIdentity'
      );
    });

    test('should throw error for missing OAuth2 token URL', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingTokenUrl = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
          AWS_ASSUME_ROLE_WEB_IDENTITY_REGION: 'us-west-2',
          AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN:
            'arn:aws:iam::123456789012:role/TestRole'
        },
        secrets: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret'
        },
        outputs: {}
      };

      await expect(script.invoke(params, contextMissingTokenUrl)).rejects.toThrow(
        'unsupported auth type: expected Basic or OAuth2ClientCredentials with AwsAssumeRoleWebIdentity'
      );
    });

    test('should throw error for missing OAuth2 client secret', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1'
      };

      const contextMissingClientSecret = {
        environment: {
          OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
          OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://auth.example.com/token',
          AWS_ASSUME_ROLE_WEB_IDENTITY_REGION: 'us-west-2',
          AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN:
            'arn:aws:iam::123456789012:role/TestRole'
        },
        secrets: {},
        outputs: {}
      };

      await expect(
        script.invoke(params, contextMissingClientSecret)
      ).rejects.toThrow(
        'unsupported auth type: expected Basic or OAuth2ClientCredentials with AwsAssumeRoleWebIdentity'
      );
    });
  });

  describe('error handler', () => {
    test('should re-throw error for framework to handle', async () => {
      const params = {
        userName: 'TestUser',
        region: 'us-east-1',
        error: new Error('Network timeout')
      };

      await expect(script.error(params, mockContext)).rejects.toThrow(
        'Network timeout'
      );
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown', async () => {
      const params = {
        userName: 'TestUser',
        reason: 'timeout'
      };

      const result = await script.halt(params, mockContext);

      expect(result.userName).toBe('TestUser');
      expect(result.reason).toBe('timeout');
      expect(result.haltedAt).toBeDefined();
      expect(result.cleanupCompleted).toBe(true);
    });

    test('should handle halt with missing params', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.userName).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
      expect(result.cleanupCompleted).toBe(true);
    });
  });
});
