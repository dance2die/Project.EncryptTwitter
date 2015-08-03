using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CryptographyInDotNet;

namespace Project.EncryptTwitter.Security.Cryptography.Demo
{
	class Program
	{
		static void Main(string[] args)
		{
			//const string original = "Very secret and important information that can not fall into the wrong hands.";
			//string original = new String('0', 140);
			//string original = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";
			string original = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";

			var hybrid = new HybridEncryption();

			var rsaParams = new RSAWithRSAParameterKey();
			rsaParams.AssignNewKey();

			var digitalSignature = new DigitalSignature();
			digitalSignature.AssignNewKey();

			Console.WriteLine("Hybrid Encryption with Integrity Check Demonstration in .NET");
			Console.WriteLine("------------------------------------------------------------");
			Console.WriteLine();

			try
			{
				var encryptedBlock = hybrid.EncryptData(
					Encoding.UTF8.GetBytes(original), rsaParams, digitalSignature);

				var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams, digitalSignature);

				//byte[] gzippedBytes = GetGZippedBytes(encryptedBlock.EncryptedData);
				//byte[] ungzippedBytes = GetUnGZippedBytes(gzippedBytes);
				byte[] gzippedBytes = Compress(encryptedBlock.EncryptedData);
				byte[] ungzippedBytes = Decompress(gzippedBytes);

				Console.WriteLine("Original Message = " + original);
				Console.WriteLine("Original Message Length: {0}", original.Length);
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
		public static byte[] Compress(byte[] buffer)
		{
			MemoryStream ms = new MemoryStream();
			using (GZipStream zip = new GZipStream(ms, CompressionMode.Compress, true))
			{
				zip.Write(buffer, 0, buffer.Length);
			}

			ms.Position = 0;
			MemoryStream outStream = new MemoryStream();

			byte[] compressed = new byte[ms.Length];
			ms.Read(compressed, 0, compressed.Length);

			byte[] gzBuffer = new byte[compressed.Length + 4];
			System.Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
			System.Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
			//return Convert.ToBase64String(gzBuffer);
			return gzBuffer;
		}

		/// <remarks>
		/// http://madskristensen.net/post/compress-and-decompress-strings-in-c
		/// </remarks>
		public static byte[] Decompress(byte[] gzBuffer)
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
	}
}
