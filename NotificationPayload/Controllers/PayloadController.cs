using Newtonsoft.Json;
using NotificationPayload.Models;
using NotificationPayload.Models.DAL;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
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
            DecryptHelper decryptHelper = new DecryptHelper();
            string ErrorPath = System.Configuration.ConfigurationManager.AppSettings["PayloadErrorPath"];
            string AdditionalAuthenticatedData = System.Configuration.ConfigurationManager.AppSettings["HostDomainName"];

            try
            {

                //Load the certificate for payload verification
                X509Certificate2 x509Certificate2 = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                    "CN=upayload-uat.phillip.com.sg, O=Phillip Securities Pte Ltd, OU=IT Operations Department, L=Singapore, S=Singapore, C=SG");

                decryptHelper.ValidateCertificate(x509Certificate2, true);

                //decrypted session key as AES KEY.
                string AESKey = decryptHelper.DecryptSessionKey(payload, x509Certificate2);
                string AADData = decryptHelper.Base64Encode(AdditionalAuthenticatedData);

                //Get the decrypted the payload(AES Decryption). 
                string decryptedPayload = decryptHelper.DecryptPayload(Convert.FromBase64String(payload.EncryptedPayload),
                                                        Convert.FromBase64String(AESKey), Convert.FromBase64String(payload.Iv),
                                                        Convert.FromBase64String(AADData));

                //Load certificate for signature verification
                var signatureVerificationCertificate = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                    "CN=api-signing-uat.sg.uobnet.com, OU=GTO-Business Technology Services 1, O=United Overseas Bank Limited, L=Singapore, S=Singapore, C=SG");

                //ValidateCertificate(signatureVerificationCertificate, false);

                if (!decryptHelper.VerifySignature(decryptedPayload, payload.PayloadSignature, signatureVerificationCertificate))
                {
                    decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, "signature mismatch");
                    throw new Exception("signature mismatch");
                }

                string eventType = string.Empty;
                var accountInfo = Transaction.DeserializeAccountData(decryptedPayload, out eventType);

                // Save the decrypted payload information in RPS table.
                OutBoundDAL outBoundDAL = new OutBoundDAL();
                outBoundDAL.SaveNotificationPayload(eventType, accountInfo);
                outBoundDAL.SavePayloadRequest(JsonConvert.SerializeObject(payload));

                return Ok(Json(new { instructionId = accountInfo.InstructionId, notificationId = accountInfo.NotificationId }).Content);
            }
            catch (Exception ex)
            {
                decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, ex.Message);
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
            DecryptHelper decryptHelper = new DecryptHelper();            
            string ErrorPath = System.Configuration.ConfigurationManager.AppSettings["PayloadErrorPath"];
            string AdditionalAuthenticatedData = System.Configuration.ConfigurationManager.AppSettings["HostDomainName"];

            try
            {                           

                //Load the certificate for payload verification
                X509Certificate2 x509Certificate2 = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                    "CN=upayload-uat.phillip.com.sg, O=Phillip Securities Pte Ltd, OU=IT Operations Department, L=Singapore, S=Singapore, C=SG");

                decryptHelper.ValidateCertificate(x509Certificate2, true);

                //decrypted session key as AES KEY.
                string AESKey = decryptHelper.DecryptSessionKey(payload, x509Certificate2);
                string AADData = decryptHelper.Base64Encode(AdditionalAuthenticatedData);

                //Get the decrypted the payload(AES Decryption). 
                string decryptedPayload = decryptHelper.DecryptPayload(Convert.FromBase64String(payload.EncryptedPayload),
                                                        Convert.FromBase64String(AESKey), Convert.FromBase64String(payload.Iv),
                                                        Convert.FromBase64String(AADData));

                //Load certificate for signature verification
                var signatureVerificationCertificate = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                    "CN=api-signing-uat.sg.uobnet.com, OU=GTO-Business Technology Services 1, O=United Overseas Bank Limited, L=Singapore, S=Singapore, C=SG");

                //ValidateCertificate(signatureVerificationCertificate, false);

                if (!decryptHelper.VerifySignature(decryptedPayload, payload.PayloadSignature, signatureVerificationCertificate))
                {
                    decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, "signature mismatch");
                    throw new Exception("signature mismatch");
                }

                string eventType = string.Empty;
                var accountInfo = Transaction.DeserializeAccountData(decryptedPayload, out eventType);

                // Save the decrypted payload information in RPS table.
                OutBoundDAL outBoundDAL = new OutBoundDAL();
                outBoundDAL.SaveNotificationPayload(eventType, accountInfo);
                outBoundDAL.SavePayloadRequest(JsonConvert.SerializeObject(payload));

                return Ok(Json(new { instructionId = accountInfo.InstructionId, notificationId = accountInfo.NotificationId }).Content);
            }
            catch (Exception ex)
            {
                decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, ex.Message);
                return InternalServerError();
            }

        }


        [HttpPost]
        [Route("api/processerrortrans")]
        public IHttpActionResult ProcessErrorTransactions()
        {
            DecryptHelper decryptHelper = new DecryptHelper();
            string ErrorPath = System.Configuration.ConfigurationManager.AppSettings["PayloadErrorPath"];
            string ErrorDirectory = System.Configuration.ConfigurationManager.AppSettings["PayloadErrorDirectory"];

            try
            {
                //Process the error files.                
                string[] fileEntries = Directory.GetFiles(ErrorDirectory);

                foreach (string fileName in fileEntries)
                {
                    var payload = decryptHelper.ProcessFile(fileName);

                    if(payload != null && !string.IsNullOrEmpty(payload.Error))
                    {
                        string LogPath = System.Configuration.ConfigurationManager.AppSettings["PayloadLogPath"];
                        string AdditionalAuthenticatedData = System.Configuration.ConfigurationManager.AppSettings["HostDomainName"];

                        //Load the certificate for payload verification
                        X509Certificate2 x509Certificate2 = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                            "CN=upayload-uat.phillip.com.sg, O=Phillip Securities Pte Ltd, OU=IT Operations Department, L=Singapore, S=Singapore, C=SG");

                        decryptHelper.ValidateCertificate(x509Certificate2, true);

                        //decrypted session key as AES KEY.
                        string AESKey = decryptHelper.DecryptSessionKey(payload, x509Certificate2);
                        string AADData = decryptHelper.Base64Encode(AdditionalAuthenticatedData);

                        //Get the decrypted the payload(AES Decryption). 
                        string decryptedPayload = decryptHelper.DecryptPayload(Convert.FromBase64String(payload.EncryptedPayload),
                                                                Convert.FromBase64String(AESKey), Convert.FromBase64String(payload.Iv),
                                                                Convert.FromBase64String(AADData));

                        //Load certificate for signature verification
                        var signatureVerificationCertificate = decryptHelper.LoadCertificate(StoreLocation.LocalMachine,
                                                            "CN=api-signing-uat.sg.uobnet.com, OU=GTO-Business Technology Services 1, O=United Overseas Bank Limited, L=Singapore, S=Singapore, C=SG");

                        //ValidateCertificate(signatureVerificationCertificate, false);

                        if (!decryptHelper.VerifySignature(decryptedPayload, payload.PayloadSignature, signatureVerificationCertificate))
                        {
                            decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, "signature mismatch");
                            throw new Exception();
                        }

                        string eventType = string.Empty;
                        var accountInfo = Transaction.DeserializeAccountData(decryptedPayload, out eventType);

                        // Save the decrypted payload information in RPS table.
                        OutBoundDAL outBoundDAL = new OutBoundDAL();
                        outBoundDAL.SaveNotificationPayload(eventType, accountInfo);
                        outBoundDAL.SavePayloadRequest(JsonConvert.SerializeObject(payload));
                    }                    
                }
                return Ok();
            }
            catch (Exception ex)
            {
               // decryptHelper.SaveEncryptedPayloadLog(payload, ErrorPath, ex.Message);
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
