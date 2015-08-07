using System;

namespace Project.EncryptTwitter.Security.Auth.Demo
{
	public static class OAuthProperties
	{
		public static string Token => "14905072-vEtN8M1WvcZ1FvPOWzfoKQLxya4TqIIUCRr7YbFKT";
		public static string TokenSecret => Environment.GetEnvironmentVariable("oauth_token_secret", EnvironmentVariableTarget.User);
		public static string ConsumerKey => "fiXvFGNTBv8z9pb0zcuvFV5jO";
		public static string ConsumerKeySecret => Environment.GetEnvironmentVariable("oauth_consumer_secret", EnvironmentVariableTarget.User);
	}
}