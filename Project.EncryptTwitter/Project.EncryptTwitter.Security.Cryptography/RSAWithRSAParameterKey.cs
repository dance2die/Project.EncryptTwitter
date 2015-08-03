using System.Security.Cryptography;

namespace Project.EncryptTwitter.Security.Cryptography
{
	public class RSAWithRSAParameterKey
	{
		const int KEY_SIZE = 2048;

		private RSAParameters _publicKey;
		private RSAParameters _privateKey;

		public void ImportKeys(string xmlString = "")
		{
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				if (!string.IsNullOrWhiteSpace(xmlString))
					rsa.FromXmlString(xmlString);

				rsa.PersistKeyInCsp = false;

				_publicKey = rsa.ExportParameters(false);
				_privateKey = rsa.ExportParameters(true);
			}
		}
		public string ExportKeys()
		{
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.ImportParameters(_privateKey);

				const bool includePrivateParameters = true;
				return rsa.ToXmlString(includePrivateParameters);
			}
		}

		public byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherbytes;
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_publicKey);

				cipherbytes = rsa.Encrypt(dataToEncrypt, false);
			}

			return cipherbytes;
		}

		public byte[] DecryptData(byte[] dataToEncrypt)
		{
			byte[] plain;
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_privateKey);

				plain = rsa.Decrypt(dataToEncrypt, false);
			}

			return plain;
		}
	}
}