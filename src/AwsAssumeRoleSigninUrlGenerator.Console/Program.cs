using AwsAssumeRoleSigninUrlGenerator;
using System;
using System.Threading.Tasks;

namespace AwsAssumeRoleSigninUrlGenerator.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            var snsReadonlyPolicy = "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"sns:GetTopicAttributes\", \"sns:List*\"],\"Resource\": \"*\"}]}";
            var consoleUrl = "https://console.aws.amazon.com/sns/v2/home?region=ap-northeast-1";
#if DEBUG
            var url = new FederatedUserConsoleUrlGenerator("AssumeRole-Test") { Policy = snsReadonlyPolicy, ConsoleUrl = consoleUrl }.GetConsoleUrl().Result;
#else
            var url = new StsUrlGenerator() { Policy = snsReadonlyPolicy, ConsoleUrl = consoleUrl }.GetConsoleUrl().Result;
#endif
            System.Console.WriteLine(url);

            System.Console.ReadLine();
        }
    }
}
