using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
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
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NotificationPayload.Models
{
    public class DecryptHelper
    {

        /// <summary>
        /// Decrypt the session key using RSA/ECB/PKCS1Padding
        /// </summary>
        /// <param name="payload">Actual Payload</param>
        /// <returns></returns>
        public string DecryptSessionKey(Payload payload, X509Certificate2 x509Certificate2)
        {           

            var ciphertext = payload.EncryptedSessionKey;
            byte[] cipherTextBytes = Convert.FromBase64String(ciphertext);

            RSACryptoServiceProvider rsaCryptoServiceProvider = (RSACryptoServiceProvider)x509Certificate2.PrivateKey;
            var asymmetricCipherKey = DotNetUtilities.GetRsaKeyPair(rsaCryptoServiceProvider);
       
            // PKCS1 v1.5 paddings
            Pkcs1Encoding eng = new Pkcs1Encoding(new RsaEngine()); 
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
        /// Decrypt the payload using decrypted session key
        /// </summary>
        /// <param name="keySize">AES key size</param>
        /// <param name="cipherAndTag">Chipher text with tag</param>
        /// <param name="aeskey">AES key</param>
        /// <param name="iv">Initialization vector(96 bytes)</param>
        /// <param name="aad">AdditionalAuthenticationData</param>
        /// <returns></returns>
        public string DecryptPayload(byte[] cipherAndTag, byte[] aeskey, byte[] iv, byte[] aad)
        {
            using (var cipherStream = new MemoryStream(cipherAndTag))
            {
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

                    var decryptedPayload = Convert.ToBase64String(plainText);
                    string result = System.Text.Encoding.UTF8.GetString(plainText);
                    return result;

                }
            }

        }

        public bool VerifySignature(string PayloadInfo, string expectedPayloadSignature, X509Certificate2 x509Certificate2)
        {
            RSA rSA = (RSA)x509Certificate2.GetRSAPublicKey();

            var rsaPublicKey = DotNetUtilities.GetRsaPublicKey(rSA);

            /* Init alg */
            ISigner signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption);

            /* Populate key */
            signer.Init(false, rsaPublicKey);

            /* Get the signature into bytes */
            var expectedSig = Convert.FromBase64String(expectedPayloadSignature);

            /* Get the bytes to be signed from the string */
            var msgBytes = Encoding.UTF8.GetBytes(PayloadInfo);

            /* Calculate the signature and see if it matches */
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);

            if (signer.VerifySignature(expectedSig))
            {
                return true;
            }
            return false;

        }


        public X509Certificate2 LoadCertificate(StoreLocation storeLocation, string certificateName)
        {
            X509Store store = new X509Store(storeLocation);

            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates;

            X509Certificate2 cert = certCollection.Cast<X509Certificate2>().FirstOrDefault(c => c.Subject == certificateName);         

            if (cert == null)
                 throw new Exception("was found in your certificate store");

            store.Close();

            return cert;
        }

        public string encrypt(string plainText, AsymmetricAlgorithm publicKey)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            RSACryptoServiceProvider rsaCryptoServiceProvider = (RSACryptoServiceProvider)publicKey;
            var asymmetricCipherKey = DotNetUtilities.GetRsaPublicKey(rsaCryptoServiceProvider);

            // PKCS1 v1.5 paddings
            Pkcs1Encoding eng = new Pkcs1Encoding(new RsaEngine());           

            eng.Init(true, asymmetricCipherKey);

            int length = plainTextBytes.Length;
            int blockSize = eng.GetInputBlockSize();
            List<byte> cipherTextBytes = new List<byte>();
            for (int chunkPosition = 0;
                chunkPosition < length;
                chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, length - chunkPosition);
                cipherTextBytes.AddRange(eng.ProcessBlock(
                    plainTextBytes, chunkPosition, chunkSize
                ));
            }
            return Convert.ToBase64String(cipherTextBytes.ToArray());
        }

        public void SaveEncryptedPayloadLog(Payload payload)
        {
            String timeStamp = DateTime.Now.ToString("dd-MM-yyyy-HH-mm-ss-ffff");
            string path = @"E:\Paynow\Logs\Payload_" + timeStamp +".txt";
            if (!File.Exists(path))
            {
                // Create a file to write to.
                using (StreamWriter sw = File.CreateText(path))
                {
                    sw.WriteLine("EncryptedPayload=" + payload.EncryptedPayload);
                    sw.WriteLine("EncryptedSessionKey=" + payload.EncryptedSessionKey);
                    sw.WriteLine("Iv=" + payload.Iv);
                    sw.WriteLine("PayloadSignature=" + payload.PayloadSignature);                   
                }
            }
        }
        

    }
}