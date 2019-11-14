using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace NotificationPayload.Models
{
    public class DecryptHelper
    {

        /// <summary>
        /// Decrypt the session key using RSA/ECB/PKCS1Padding
        /// </summary>
        /// <param name="payload">Actual Payload</param>
        /// <returns></returns>
        public static string DecryptSessionKey(Payload payload)
        {
            var privatekey = @"";
            var ciphertext = @"";

            byte[] privateKeyInBytes = Convert.FromBase64String(privatekey);
            byte[] cipherTextBytes = Convert.FromBase64String(ciphertext);

            var privateKeyLength = privateKeyInBytes.Length;
            var cipherTextLength = cipherTextBytes.Length;

            var rsaPrivateCrtKey = (RsaPrivateCrtKeyParameters)GetMerchantPrivateKey(privateKeyInBytes);
            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaPrivateCrtKey);

            CspParameters cspParameters = new CspParameters();
            cspParameters.KeyContainerName = "MyKeyContainer";
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(4096, cspParameters);
            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

            var asymmetricCipherKey = DotNetUtilities.GetRsaKeyPair(rsaCryptoServiceProvider);




            //Pure mathematical RSA implementation
            //RsaEngine eng = new RsaEngine();

            // PKCS1 v1.5 paddings
            Pkcs1Encoding eng = new Pkcs1Encoding(new RsaEngine());

            // PKCS1 OAEP paddings
            // OaepEncoding eng = new OaepEncoding(new RsaEngine());

            //eng.Init(false, keys.Private);

            eng.Init(false, asymmetricCipherKey.Private);
            

            int length = cipherTextBytes.Length;
            int blockSize = eng.GetInputBlockSize();
            List<byte> plainTextBytes = new List<byte>();

            for (int chunkPosition = 0; chunkPosition < length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, length - chunkPosition);
                plainTextBytes.AddRange(eng.ProcessBlock(cipherTextBytes, chunkPosition, chunkSize));
            }
            var decrypted = Encoding.UTF8.GetString(plainTextBytes.ToArray());


            //Now  Trying to extract private key from pem file.

            //var vvv = PrivateKeyFromPemFile(@"C:\Users\sathiya\my-key.pem");

            return decrypted;
        }

        /// <summary>
        /// Get RSAPrivateCrtKeyParameters
        /// </summary>
        /// <param name="privateKeyBite"></param>
        /// <returns></returns>
        public static RsaPrivateCrtKeyParameters GetMerchantPrivateKey(byte[] privateKeyBite)
        {
            var akp = PrivateKeyFactory.CreateKey(privateKeyBite);
            return (RsaPrivateCrtKeyParameters)akp;
        }




        /// <summary>
        /// Decrypt the payload using decrypted session key
        /// </summary>
        /// <param name="keySize">AES key size</param>
        /// <param name="cipherAndTag">Chipher text with tag</param>
        /// <param name="aeskey">AES key</param>
        /// <param name="iv">Initialization vector(96 bytes)</param>
        /// <param name="aad">AdditionalAuthenticationData</param>
        /// <returns></returns>
        public static string DecryptPayload(int keySize, byte[] cipherAndTag, byte[] aeskey, byte[] iv, byte[] aad)
        {
            byte[] arr_plane = null;
            using (var cipherStream = new MemoryStream(cipherAndTag))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(aeskey), 128, iv, aad);
                cipher.Init(false, parameters);

                // Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(cipherAndTag.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);

                cipher.DoFinal(plainText, len);
                arr_plane = plainText; 
                var nn = Convert.ToBase64String(arr_plane); 
                string result = System.Text.Encoding.UTF8.GetString(arr_plane);
                return nn;
            }
        }

    }
}