using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NotificationPayload.Models;
using NotificationPayload.Models.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
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

                //Get the decrypted session key from the payload(RSA Decryption).
                string decryptedSessionKey = DecryptHelper.DecryptSessionKey(payload);

                //Get the decrypted the payload(AES Decryption).
                string decryptedPayload = DecryptHelper.DecryptPayload(256, Convert.FromBase64String(payload.EncryptedPayload),
                                          Convert.FromBase64String(decryptedSessionKey), Convert.FromBase64String(payload.Iv),
                                          Convert.FromBase64String("cmFuZG9t"));

               // var vv = @"{ 'event':'credit', 'data' : {'AccountName': 'PayNow', 'AccountType': 'Savings'} }";

                string eventType = string.Empty;
                var accountInfo = Account.DeserializeAccountData(decryptedPayload, out eventType);

                //Save the decrypted payload information in RPS table.
                OutBoundDAL outBoundDAL = new OutBoundDAL();
                outBoundDAL.SaveNotificationPayload(eventType, accountInfo);

                return Ok();
            }
            catch
            {
                return InternalServerError();
            }
           
        }

    }
}
