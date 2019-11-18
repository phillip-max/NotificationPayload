using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Security.Cryptography;
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
        public string DecryptSessionKey(Payload payload)
        {
            //var privatekey = GetPrivateKey(@"D:\Certificates\PSPL_UOB_Paynow_C\utwoway-uat.phillip.com.key");
            //var ciphertext = payload.EncryptedSessionKey;

            var privatekey = @"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";
            var ciphertext = @"sbevHJ1bQjmDnOce7tgDbjsrI37sPN8Uap1LPUh2Us4B9cbLsIWI0kOyAx+5fa6yI6BcvCBHA2lBNjUlislDPrgy2WXsJ6fnbONV4zZNNFdqEoKfU05ihB5aDPy6Z5se96oN/0OIaW4QcdicC7udsiQWMLiSj4JhfENEMoZQGQF9TL3KfDpUJc9Iej/WMh2IdocsaWuL8xXfcT1PFKsKhKgO4PuRcxx+Ao9TI64TmurWRpK5R/tzudkI11TdSYM2/YTG89ubZp9qyVkwoiihNHADuKEmj5IfSRS2MF1DpuY0P21JDINjBftHqjomAnLxj2R1bxJhRzUp9PriSJiNWq3+ImkRLs7dYRZWpTaXs4NptwZXgxxHAuiNzmBJX1yujp42/PVmwiewbcPlIi/95MQ64VZeUlN3exNZ8NIyRuCS1qEblqcSQvClhbBa3KtRIRCtt0JDlZKLGcDrb6HvZN13NvFhA/XvNJrX445qceaVdjfTFaKCbrFrLcqM+EnwnpOkEMZERQnxkoVKr2duQJhs32q44i561DDq1a5FEHaljGq0eOo1ChHpyS/KPwbjmhfbea6EjjsMqqwloyZ3RQ//g8yn3tJiyJD7y1JmGTMtDHTlCmkBgna+e0Atftjups5oltmC6XELrb2GMRgsJLk2tv2P4z3jO5/ghMvGug4=";
            byte[] privateKeyInBytes = Convert.FromBase64String(privatekey);
            byte[] cipherTextBytes = Convert.FromBase64String(ciphertext);

            var rsaPrivateCrtKey = (RsaPrivateCrtKeyParameters)GetMerchantPrivateKey(privateKeyInBytes);

            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaPrivateCrtKey);
            CspParameters cspParameters = new CspParameters
            {
                KeyContainerName = "MyKeyContainer"
            };
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(4096, cspParameters);
            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

            //if (!this.VerifySignature(rsaCryptoServiceProvider, payload.PayloadSignature))
            //{
            //    throw new Exception();
            //}

            var asymmetricCipherKey = DotNetUtilities.GetRsaKeyPair(rsaCryptoServiceProvider);           

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
        /// Get Private key from the .key format file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns>private key</returns>
        public static String GetPrivateKey(string filePath)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = File.OpenText(filePath))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keyPair.Private);
            pemWriter.Writer.Flush();
            
            var Privatekey = textWriter.ToString();

            if(Privatekey.Contains("-----BEGIN RSA PRIVATE KEY-----"))
                Privatekey = Privatekey.Replace("-----BEGIN RSA PRIVATE KEY-----", "");
            if (Privatekey.Contains("-----END RSA PRIVATE KEY-----"))
                Privatekey = Privatekey.Replace("-----END RSA PRIVATE KEY-----", "");

            return Privatekey.Trim();
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

        public bool VerifySignature(RSACryptoServiceProvider rSACryptoService, string payloadSignature)
        {
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Convert.FromBase64String(payloadSignature));

            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rSACryptoService);
            rsaDeformatter.SetHashAlgorithm("SHA256");

            if (!rsaDeformatter.VerifySignature(hash, Convert.FromBase64String(payloadSignature)))
                return false;

            return true;
        }

    }
}