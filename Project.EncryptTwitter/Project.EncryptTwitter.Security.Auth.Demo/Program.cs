using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Tweetinvi;
using Tweetinvi.Core.Credentials;
using TweetSharp;
using Stream = System.IO.Stream;

namespace Project.EncryptTwitter.Security.Auth.Demo
{
	public class Program
	{
		public static void Main(string[] args)
		{
			//Test1();
			//TestUsingTweetSharp();
			//TestWithTweetSharpXAuth();

			//TestWithTweetinvi();
		}

		private static void TestWithTweetinvi()
		{
			// Set up your credentials (https://apps.twitter.com)
			var twitterCredentials = new TwitterCredentials(
				OAuthProperties.Token, OAuthProperties.TokenSecret, 
				OAuthProperties.ConsumerKey, OAuthProperties.ConsumerKeySecret);

			// Publish a tweet
			Tweet.PublishTweet("@TweetinviApi rocks!");

			// Get the details of the Logged User
			var loggedUser = User.GetLoggedUser();

			// Get my Home Timeline
			var tweets = Timeline.GetHomeTimeline();
		}

		private static void TestWithTweetSharpXAuth()
		{
			// OAuth Access Token Exchange
			TwitterService service = new TwitterService(OAuthProperties.ConsumerKey, OAuthProperties.ConsumerKeySecret);

			Console.WriteLine("Enter Username...");
			string username = Console.ReadLine();
			Console.WriteLine("Enter Password...");
			string password = Console.ReadLine();
			OAuthAccessToken accessToken = service.GetAccessTokenWithXAuth(username, password);

			service.AuthenticateWith(accessToken.Token, accessToken.TokenSecret);
			var verifyCredentialsOptions = new VerifyCredentialsOptions {IncludeEntities = true};
			TwitterUser user = service.VerifyCredentials(verifyCredentialsOptions);
		}

		private static void TestUsingTweetSharp()
		{
			// Pass your credentials to the service
			TwitterService service = new TwitterService(OAuthProperties.ConsumerKey, OAuthProperties.ConsumerKeySecret);

			// Step 1 - Retrieve an OAuth Request Token
			OAuthRequestToken requestToken = service.GetRequestToken();

			// Step 2 - Redirect to the OAuth Authorization URL
			Uri uri = service.GetAuthorizationUri(requestToken);
			Process.Start(uri.ToString());

			// Step 3 - Exchange the Request Token for an Access Token
			string verifier = "123456"; // <-- This is input into your application by your user
			//OAuthAccessToken access = service.GetAccessToken(requestToken, verifier);
			OAuthAccessToken access = service.GetAccessToken(requestToken);

			// Step 4 - User authenticates using the Access Token
			service.AuthenticateWith(access.Token, access.TokenSecret);
			//IEnumerable<TwitterStatus> mentions = service.ListTweetsMentioningMe(new ListTweetsMentioningMeOptions {Count = 10});
			TwitterStatus twitterStatus = service.SendTweet(new SendTweetOptions {Status = "Hello #TweetSharp"});
		}

		private static void Test1()
		{
			// Authenticate to Twitter using OAuth
			/// http://www.codeproject.com/Articles/247336/Twitter-OAuth-authentication-using-Net

			var status = "Updating status via REST API if this works v3";
			var postBody = "status=" + Uri.EscapeDataString(status);
			var request = GetTwitterWebRequest(status);
			using (Stream stream = request.GetRequestStream())
			{
				byte[] content = Encoding.ASCII.GetBytes(postBody);
				stream.Write(content, 0, content.Length);
			}

			WebResponse response = request.GetResponse();
			using (var reader = new StreamReader(response.GetResponseStream()))
			{
				string objText = reader.ReadToEnd();
				//JavaScriptSerializer js = new JavaScriptSerializer();
				//MyObject myojb = (MyObject)js.Deserialize(objText, typeof(MyObject));
			}
		}

		private static HttpWebRequest GetTwitterWebRequest(string status)
		{
			var oauth_token = OAuthProperties.Token;
			var oauth_token_secret = OAuthProperties.TokenSecret;
			var oauth_consumer_key = OAuthProperties.ConsumerKey;
			var oauth_consumer_secret = OAuthProperties.ConsumerKeySecret;

			var oauth_version = "1.0";
			var oauth_signature_method = "HMAC-SHA1";
			var oauth_nonce = Convert.ToBase64String(
				new ASCIIEncoding().GetBytes(
					DateTime.Now.Ticks.ToString()));
			var timeSpan = DateTime.UtcNow
						   - new DateTime(1970, 1, 1, 0, 0, 0, 0,
							   DateTimeKind.Utc);
			var oauth_timestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString();
			var resource_url = "https://api.twitter.com/1.1/statuses/update.json";

			var baseFormat = "oauth_consumer_key={0}&oauth_nonce={1}&oauth_signature_method={2}" +
							 "&oauth_timestamp={3}&oauth_token={4}&oauth_version={5}&status={6}";

			var baseString = string.Format(baseFormat,
				oauth_consumer_key,
				oauth_nonce,
				oauth_signature_method,
				oauth_timestamp,
				oauth_token,
				oauth_version,
				Uri.EscapeDataString(status)
			);

			baseString = string.Concat("POST&", Uri.EscapeDataString(resource_url),
				"&", Uri.EscapeDataString(baseString));

			var compositeKey = string.Concat(Uri.EscapeDataString(oauth_consumer_secret),
				"&", Uri.EscapeDataString(oauth_token_secret));

			string oauth_signature;
			using (HMACSHA1 hasher = new HMACSHA1(Encoding.ASCII.GetBytes(compositeKey)))
			{
				oauth_signature = Convert.ToBase64String(
					hasher.ComputeHash(Encoding.ASCII.GetBytes(baseString)));
			}

			var headerFormat =
				"OAuth oauth_nonce=\"{0}\", oauth_signature_method=\"{1}\", " +
				"oauth_timestamp=\"{2}\", oauth_consumer_key=\"{3}\", " +
				"oauth_token=\"{4}\", oauth_signature=\"{5}\", " +
				"oauth_version=\"{6}\"";

			var authHeader = string.Format(headerFormat,
				Uri.EscapeDataString(oauth_nonce),
				Uri.EscapeDataString(oauth_signature_method),
				Uri.EscapeDataString(oauth_timestamp),
				Uri.EscapeDataString(oauth_consumer_key),
				Uri.EscapeDataString(oauth_token),
				Uri.EscapeDataString(oauth_signature),
				Uri.EscapeDataString(oauth_version)
				);



			ServicePointManager.Expect100Continue = false;

			var request = (HttpWebRequest)WebRequest.Create(resource_url);
			request.Headers.Add("Authorization", authHeader);
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";

			return request;
		}
	}
}
