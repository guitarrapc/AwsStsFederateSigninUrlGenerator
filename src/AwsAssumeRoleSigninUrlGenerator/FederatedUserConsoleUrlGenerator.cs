using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace AwsAssumeRoleSigninUrlGenerator
{
    public class FederatedUserConsoleUrlGenerator
    {
        private static AmazonSecurityTokenServiceClient stsClient;
        private static HttpClient httpClient = new HttpClient();
        private string federatedSigninUrl = "https://signin.aws.amazon.com/federation";

        /// <summary>
        /// A policy restrict access with temporary IAM Policy.
        /// ATTENTION : Base IAMUser must have grant access for GetFederationToken Policy.
        /// </summary>
        /// <remarks>
        /// NOTE : Make sure temporary user will be restricted within base IAM User Policy access.
        /// </remarks>
        /// <example>
        /// In this sample, SNS readonly access will be apply.
        /// {
        ///     "Version": "2012-10-17",
        ///     "Statement": [{
        ///         "Effect": "Allow",
        ///         "Action": "sts:GetFederationToken",
        ///         "Resource": "*"
        ///     }]
        /// }
        /// </example>
        public string Policy { get; set; } = "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"sns:GetTopicAttributes\", \"sns:List*\"],\"Resource\": \"*\"}]}";
        /// <summary>
        /// ConsoleUrl when issued. You should better control url which user wants access.
        /// </summary>
        public string ConsoleUrl { get; set; } = "https://console.aws.amazon.com/";

        /// <summary>
        /// min 15min, max 12hour
        /// </summary>
        public int SessionDurationSec { get; set; } = 60 * 15; 
        public string UserName { get; set; } = "federated-user";

        public FederatedUserConsoleUrlGenerator()
        {
            stsClient = new AmazonSecurityTokenServiceClient();
        }

        public FederatedUserConsoleUrlGenerator(string profile)
        {
            var credential = GetCredential(profile);
            stsClient = new AmazonSecurityTokenServiceClient(credential);
        }

        public async Task<string> GetConsoleUrl()
        {
            var signinUrl = await GetSigninTokenUrl();
            var res = await httpClient.GetAsync(signinUrl);
            var signinTokenJson = await res.Content.ReadAsStringAsync();
            var credential = JsonConvert.DeserializeObject<SessionCredential>(signinTokenJson);
            var signInToken = Uri.EscapeDataString(credential.SigninToken);

            var loginUrl = $"{federatedSigninUrl}?Action=login&Destination={ConsoleUrl}&SigninToken={signInToken}&SessionDuration={SessionDurationSec}";
            return loginUrl;
        }

        private async Task<string> GetSigninTokenUrl()
        {
            var request = new GetFederationTokenRequest(UserName);
            request.DurationSeconds = SessionDurationSec;
            request.Policy = Policy;

            var response = await stsClient.GetFederationTokenAsync(request);
            var credential = response.Credentials;

            var json = JsonConvert.SerializeObject(new SessionJson(credential.AccessKeyId, credential.SecretAccessKey, credential.SessionToken));
            var url = $"{federatedSigninUrl}?Action=getSigninToken&Session={Uri.EscapeDataString(json)}";
            return url;
        }

        private static AWSCredentials GetCredential(string profileName)
        {
            var netSDK = new NetSDKCredentialsFile();
            if (netSDK.TryGetProfile(profileName, out CredentialProfile profile) && AWSCredentialsFactory.TryGetAWSCredentials(profile, netSDK, out AWSCredentials credentials))
            {
                return credentials;
            }
            throw new NullReferenceException($"{nameof(profileName)} not found from exsiting profile list. Make sure you have set Profile");
        }
    }

    public class SessionJson
    {
        public string sessionId { get; set; }
        public string sessionKey { get; set; }
        public string sessionToken { get; set; }

        public SessionJson(string id, string key, string token)
        {
            sessionId = id;
            sessionKey = key;
            sessionToken = token;
        }
    }

    public class SessionCredential
    {
        public string SigninToken { get; set; }

        public SessionCredential(string token)
        {
            SigninToken = token;
        }
    }
}
