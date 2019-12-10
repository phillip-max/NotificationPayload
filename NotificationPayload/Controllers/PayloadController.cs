using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NotificationPayload.Models;
using NotificationPayload.Models.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Http;

namespace NotificationPayload.Controllers
{
    public class PayloadController : ApiController
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        [HttpPost]
        [Route("api/decryptpayload")]
        public IHttpActionResult DecryptPayload(Payload payload)
        {
            try
            {

                DecryptHelper decryptHelper = new DecryptHelper();

                X509Certificate2 x509Certificate2 = decryptHelper.LoadCertificate(StoreLocation.LocalMachine, "CN=upayload-uat.phillip.com.sg, O=Phillip Securities Pte Ltd, OU=IT Operations Department, L=Singapore, S=Singapore, C=SG");

                if (x509Certificate2 == null)
                    throw new Exception("A x509 certificate and string for decryption must be provided");

                if (!x509Certificate2.HasPrivateKey)
                    throw new Exception("x509 certicate does not contain a private key for decryption");

                //Get the decrypted session key from the payload(RSA Decryption).
                string decryptedSessionKey = decryptHelper.DecryptSessionKey(payload, x509Certificate2);

                 decryptedSessionKey = "Mt61nP8IHxyOT+Z4Z0QkP8xlxLSxkxqIITBKaepFQ5k=";


                //Get the decrypted the payload(AES Decryption).
                string decryptedPayload = decryptHelper.DecryptPayload(Convert.FromBase64String(payload.EncryptedPayload),
                                          Convert.FromBase64String(decryptedSessionKey), Convert.FromBase64String(payload.Iv),
                                          Convert.FromBase64String("cmFuZG9t"));

                if (!decryptHelper.VerifySignature(decryptedPayload, payload.PayloadSignature, x509Certificate2))
                {
                    throw new Exception("Signature matching failed");
                }               

                string eventType = string.Empty;
                var accountInfo = Account.DeserializeAccountData(decryptedPayload, out eventType);

                //Save the decrypted payload information in RPS table.
                OutBoundDAL outBoundDAL = new OutBoundDAL();
                outBoundDAL.SaveNotificationPayload(eventType, accountInfo);               

                return Ok(Json(new { instructionId = accountInfo.InstructionId, notificationId =  accountInfo.NotificationId }).Content);
            }
            catch
            {
                return InternalServerError();
            }

        }



        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        [HttpPost]
        [Route("api/decryptpayloadtest")]
        public IHttpActionResult DecryptPayloadTest(Payload payload)
        {
            try
            {
                DecryptHelper decryptHelper = new DecryptHelper();

                X509Certificate2 x509Certificate2 = decryptHelper.LoadCertificate(StoreLocation.LocalMachine, "storeName=My"); 
     

                payload.EncryptedSessionKey = decryptHelper.encrypt("ASP.NET Web API is a framework that makes it easy to build HTTP services that reach a broad range of clients, including browsers and mobile devices. ASP.NET Web API is an ideal platform for building RESTful applications on the .NET Framework.", x509Certificate2.PublicKey.Key);

                if (x509Certificate2 == null)
                    throw new Exception("A x509 certificate and string for decryption must be provided");

                if (!x509Certificate2.HasPrivateKey)
                    throw new Exception("x509 certicate does not contain a private key for decryption");               


                //decrypted session key .
                string decryptedSessionKey = decryptHelper.DecryptSessionKey(payload, x509Certificate2);

                payload.EncryptedPayload = @"0JFmXIgMHaAlcPetQYe11BywdScjNTqfLap3YFg9rNkqLzE+zKqMDbPU7HAgJRlRIRQw4LqFYP53iuwnZ/IJ82upFFLz+tVYVKnQUFGI6G60oTLnb6evzauGleX4GlXiHcnj/RjvYAVvEYU0X8fjXCki0D6glWmQMGq4WOaTlO7EUSkDD7OPYoZXz9gie6WxM64TIIEW/Jk9OKLUgeU4gWt4tXOHLinTlEw+FtukVnUwkCNRHpS+SUGu40EjE5io5mKK3CUqmDI43bKMGWtz2aU=";
                payload.Iv = @"9pXokzIiEaC0y7b6shqtyrHcEe7Ttj4EdbDmVpX7tNos0X3PmWTfuVTf/+vyxHkUnCo7N1HBwWFkPMFBipP3u6bFgWezIBTSExEWS+PbugBVzlc3Aw5gvZs0w0AaKOFE";
                var aesKey = "yaYkqeWhZ5p3miJgfzqNv2PdahxVlPRRKc5XRugeU/I=";
                //Get the decrypted the payload(AES Decryption).

                string decryptedPayload = decryptHelper.DecryptPayload(Convert.FromBase64String(payload.EncryptedPayload),
                                                        Convert.FromBase64String(aesKey), Convert.FromBase64String(payload.Iv),
                                                        Convert.FromBase64String("cmFuZG9t"));


                if (!decryptHelper.VerifySignature(decryptedPayload, payload.PayloadSignature, x509Certificate2))
                {
                    throw new Exception();
                }

                string eventType = string.Empty;

                var accountInfo = Account.DeserializeAccountData(decryptedPayload, out eventType);

               // Save the decrypted payload information in RPS table.
                OutBoundDAL outBoundDAL = new OutBoundDAL();
                outBoundDAL.SaveNotificationPayload(eventType, accountInfo);

                return Ok();
            }
            catch
            {
                return InternalServerError();
            }

        }

        [HttpGet]
        [Route("api/testget")]
        public IHttpActionResult TestGet(Payload payload)
        {
            return Ok("Api Called");
        }

  }
}
