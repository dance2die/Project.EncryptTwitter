using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Project.EncryptTwitter.Security.Auth.Demo
{
	public class Program
	{
		public static void Main(string[] args)
		{
			// Authenticate to Twitter using OAuth
			/// http://www.codeproject.com/Articles/247336/Twitter-OAuth-authentication-using-Net

			var oauth_token = "14905072-vEtN8M1WvcZ1FvPOWzfoKQLxya4TqIIUCRr7YbFKT";
			var oauth_token_secret = Environment.GetEnvironmentVariable("oauth_token_secret", EnvironmentVariableTarget.User);
			var oauth_consumer_key = "fiXvFGNTBv8z9pb0zcuvFV5jO";
			var oauth_consumer_secret = Environment.GetEnvironmentVariable("oauth_consumer_secret", EnvironmentVariableTarget.User);

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
			var status = "Updating status via REST API if this works v2";

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
			using (HMACSHA1 hasher = new HMACSHA1(ASCIIEncoding.ASCII.GetBytes(compositeKey)))
			{
				oauth_signature = Convert.ToBase64String(
					hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(baseString)));
			}

			var headerFormat = "OAuth oauth_nonce=\"{0}\", oauth_signature_method=\"{1}\", " +
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

			var postBody = "status=" + Uri.EscapeDataString(status);

			ServicePointManager.Expect100Continue = false;

			HttpWebRequest request = (HttpWebRequest)WebRequest.Create(resource_url);
			request.Headers.Add("Authorization", authHeader);
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";
			using (Stream stream = request.GetRequestStream())
			{
				byte[] content = ASCIIEncoding.ASCII.GetBytes(postBody);
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
	}
}
