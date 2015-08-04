using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Project.EncryptTwitter.Security.Cryptography.Demo
{
	class Program
	{
		static void Main()
		{
			//const string original = "Very secret and important information that can not fall into the wrong hands.";
			//string original = new String('0', 127);
			string original = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrs";
			original = GenerateRandomText();
			//string original = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";
			//string original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam non dictum diam. Donec feugiat libero sed arcu interdum consectetur vitae amet.";
			//string original = @"?=??Y@쳘?{?? &긳 ? v ? ";

			var hybrid = new HybridEncryption();

			var rsaParams = new RSAWithRSAParameterKey();
			rsaParams.ImportKeys();

			var digitalSignature = new DigitalSignature();
			digitalSignature.AssignNewKey();

			Console.WriteLine("Hybrid Encryption with Integrity Check Demonstration in .NET");
			Console.WriteLine("------------------------------------------------------------");
			Console.WriteLine();

			try
			{
				var originalData = Encoding.UTF8.GetBytes(original);

				byte[] compressedBytes = Compress(originalData);
				byte[] decompressedBytes = Decompress(compressedBytes);

				var encryptedBlock = hybrid.EncryptData(
					originalData, rsaParams, digitalSignature);

				var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams, digitalSignature);

				//byte[] gzippedBytes = GetGZippedBytes(encryptedBlock.EncryptedData);
				//byte[] ungzippedBytes = GetUnGZippedBytes(gzippedBytes);
				byte[] gzippedBytes = Compress(encryptedBlock.EncryptedData);
				byte[] ungzippedBytes = Decompress(gzippedBytes);

				Console.WriteLine("Original Message = " + original);
				Console.WriteLine("Original Message Length: {0}", original.Length);
				Console.WriteLine("Compressed Original Message = " + Convert.ToBase64String(compressedBytes));
				Console.WriteLine("Compressed Original Message Length: {0}", compressedBytes.Length);
				Console.WriteLine("DeCompressed Original Message = " + Convert.ToBase64String(decompressedBytes));
				Console.WriteLine("DeCompressed Original Message Length: {0}", decompressedBytes.Length);
				Console.WriteLine("Encrypted Data: {0}", Convert.ToBase64String(encryptedBlock.EncryptedData));
				Console.WriteLine("Encrypted Data Size: {0}", encryptedBlock.EncryptedData.Length);
				Console.WriteLine("GZipped Encrypted Data: {0}", Convert.ToBase64String(gzippedBytes));
				Console.WriteLine("GZipped Encrypted Data Size: {0}", gzippedBytes.Length);
				Console.WriteLine("UnGZipped Encrypted Data: {0}", Convert.ToBase64String(ungzippedBytes));
				Console.WriteLine("UnGZipped Encrypted Data Size: {0}", ungzippedBytes.Length);
				Console.WriteLine();
				Console.WriteLine("Message After Decryption = " + Encoding.UTF8.GetString(decrpyted));
			}
			catch (CryptographicException ex)
			{
				Console.WriteLine("Error : " + ex.Message);
			}

			Console.ReadLine();
		}

		private static byte[] GetGZippedBytes(byte[] data)
		{
			using (MemoryStream outStream = new MemoryStream())
			using (GZipStream gZipStream = new GZipStream(outStream, CompressionMode.Compress, false))
			using (MemoryStream inStream = new MemoryStream(data))
			{
				//gz.Write(data, 0, data.Length);
				inStream.CopyTo(gZipStream);
				return outStream.ToArray();
			}
		}
		private static byte[] GetUnGZippedBytes(byte[] data)
		{
			using (MemoryStream inputStream = new MemoryStream(data))
			using (GZipStream gZipStream = new GZipStream(inputStream, CompressionMode.Decompress, false))
			using (MemoryStream outputStream = new MemoryStream())
			{
				//gZipStream.Read(data, 0, data.Length);
				//return inputStream.ToArray();
				gZipStream.CopyTo(outputStream);
				return outputStream.ToArray();
			}
		}

		/// <remarks>
		/// http://madskristensen.net/post/compress-and-decompress-strings-in-c
		/// </remarks>
		private static byte[] Compress(byte[] buffer)
		{
			MemoryStream ms = new MemoryStream();
			using (GZipStream zip = new GZipStream(ms, CompressionMode.Compress, true))
			{
				zip.Write(buffer, 0, buffer.Length);
			}

			ms.Position = 0;

			byte[] compressed = new byte[ms.Length];
			ms.Read(compressed, 0, compressed.Length);

			byte[] gzBuffer = new byte[compressed.Length + 4];
			Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
			Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
			//return Convert.ToBase64String(gzBuffer);
			return gzBuffer;
		}

		/// <remarks>
		/// http://madskristensen.net/post/compress-and-decompress-strings-in-c
		/// </remarks>
		private static byte[] Decompress(byte[] gzBuffer)
		{
			using (MemoryStream ms = new MemoryStream())
			{
				int msgLength = BitConverter.ToInt32(gzBuffer, 0);
				ms.Write(gzBuffer, 4, gzBuffer.Length - 4);

				byte[] buffer = new byte[msgLength];

				ms.Position = 0;
				using (GZipStream zip = new GZipStream(ms, CompressionMode.Decompress))
				{
					zip.Read(buffer, 0, buffer.Length);
				}

				//return Encoding.UTF8.GetString(buffer);
				return buffer;
			}
		}

		/// <remarks>
		/// http://stackoverflow.com/a/1344242/4035
		/// </remarks>
		private static string GenerateRandomText()
		{
			var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			var random = new Random();
			var result = new string(
				Enumerable.Repeat(chars, 127)
						  .Select(text => text[random.Next(text.Length)])
						  .ToArray());
			return result;
		}
	}
}
