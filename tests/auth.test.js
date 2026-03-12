import { getAwsCredentials } from '../src/auth.mjs';

describe('AWS Credentials Authentication', () => {
  beforeEach(() => {
    // Mock console to avoid noise in tests
    global.console.log = () => {};
    global.console.error = () => {};
  });

  describe('Basic Auth', () => {
    test('should return static credentials for basic auth', async () => {
      const params = {
        basic: {
          username: 'AKIAIOSFODNN7EXAMPLE',
          password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
      };

      const provider = await getAwsCredentials(params);
      const credentials = await provider();

      expect(credentials).toEqual({
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
      });
    });
  });

  describe('OAuth2 + AWS AssumeRoleWithWebIdentity', () => {
    test('should throw error when neither basic nor clientCredentials provided', async () => {
      await expect(getAwsCredentials({})).rejects.toThrow(
        'auth must provide either Basic credentials or OAuth2 with AWS AssumeRoleWebIdentity'
      );
    });

    // Note: Full integration tests for OAuth2 + AssumeRoleWithWebIdentity require:
    // 1. Mocking getClientCredentialsToken from @sgnl-actions/utils
    // 2. Mocking AWS STS AssumeRoleWithWebIdentityCommand
    // These are better suited for integration/e2e tests or scenarios.yaml
  });
});
