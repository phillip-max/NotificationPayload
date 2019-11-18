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

                //Get the decrypted session key from the payload(RSA Decryption).
                string decryptedSessionKey = decryptHelper.DecryptSessionKey(payload);

                //Get the decrypted the payload(AES Decryption).
                string decryptedPayload = DecryptHelper.DecryptPayload(256, Convert.FromBase64String(payload.EncryptedPayload),
                                          Convert.FromBase64String(decryptedSessionKey), Convert.FromBase64String(payload.Iv),
                                          Convert.FromBase64String("cmFuZG9t"));

               //var vv = @"{ 'event':'credit', 'data' : {'AccountName': 'PayNow', 'AccountType': 'Savings'} }";

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

                //Below plain text is encrypted in java RSA encryption

                // The decision almost certainly paves the way for a major Supreme Court case over President Trump’s stonewalling of congressional oversight efforts.

                //Java generated private key is below.

                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

                //Java Generated encrypted text below.

                //sbevHJ1bQjmDnOce7tgDbjsrI37sPN8Uap1LPUh2Us4B9cbLsIWI0kOyAx+5fa6yI6BcvCBHA2lBNjUlislDPrgy2WXsJ6fnbONV4zZNNFdqEoKfU05ihB5aDPy6Z5se96oN/0OIaW4QcdicC7udsiQWMLiSj4JhfENEMEMoZQGQF9TL3KfDpUJc9Iej/WMh2IdocsaWuL8xXfcT1PFKsKhKgO4PuRcxx+Ao9TI64TmurWRpK5R/tzudkI11TdSYM2/YTG89ubZp9qyVkwoiihNHADuKEmj5IfSRS2MF1DpuY0P21JDINjBftHqjomAnLxj2R1bxJhRzUp9PriSJiNWqIm3+ImkRLs7dYRZWpTaXs4NptwZXgxxHAuiNzmBJX1yujp42/PVmwiewbcPlIi/95MQ64VZeUlN3exNZ8NIyRuCS1qEblqcSQvClhbBa3KtRIRCtt0JDlZKLGcDrb6HvZN13NvFhA/XvNJrX445qceaVdjfTFaKCbrFrLcqM+EnwnpOkEMZERoVQnxkoVKr2duQJhs32q44i561DDq1a5FEHaljGq0eOo1ChHpyS/KPwbjmhfbea6EjjsMqqwloyZ3RQ//g8yn3tJiyJD7y1JmGTMtDHTlCmkBgna+e0Atftjups5oltmC6XELrb2GMRgsJLk2tv2P4z3jO5/ghMvGug4=

                //decrypted session key .
                string decryptedSessionKey = decryptHelper.DecryptSessionKey(payload);


                //Following text decrypted using AES.

                /* This will leave me either destitute*/

                //Java generated IV
                //v4zc9N9vcBHVuafkh25/sHqGT16AywVkapJf6dl9eAuoi16jWrUUaZEQd13C/1aTEypcn/7oAJITyjtJvdR+9twEc4AZ7oUApY8iOlhe9tcxWtfRymmo9W54aqIDYbmh
                //Java generated AAD data
                //cmFuZG9t
                //Java generated AES key 
                //puaK0wv2KVo1I5QxA/m068LedjaoUXnI1jH8ZVGkGcM=
                //Java generated encrypted text
                //var encryptedtext = @"E+G2cpS7E/ipwFJjrmLdSNlwVNysdvOBKD1n+5lKV58rtllMOfIGlUtKYZpEyl60f4gq";

                payload.EncryptedPayload = @"0JFmXIgMHaAlcPetQYe11BywdScjNTqfLap3YFg9rNkqLzE+zKqMDbPU7HAgJRlRIRQw4LqFYP53iuwnZ/IJ82upFFLz+tVYVKnQUFGI6G60oTLnb6evzauGleX4GlXiHcnj/RjvYAVvEYU0X8fjXCki0D6glWmQMGq4WOaTlO7EUSkDD7OPYoZXz9gie6WxM64TIIEW/Jk9OKLUgeU4gWt4tXOHLinTlEw+FtukVnUwkCNRHpS+SUGu40EjE5io5mKK3CUqmDI43bKMGWtz2aU=";
                payload.Iv = @"9pXokzIiEaC0y7b6shqtyrHcEe7Ttj4EdbDmVpX7tNos0X3PmWTfuVTf/+vyxHkUnCo7N1HBwWFkPMFBipP3u6bFgWezIBTSExEWS+PbugBVzlc3Aw5gvZs0w0AaKOFE";
                var aesKey = "yaYkqeWhZ5p3miJgfzqNv2PdahxVlPRRKc5XRugeU/I=";
                //Get the decrypted the payload(AES Decryption).

                string decryptedPayload = DecryptHelper.DecryptPayload(256, Convert.FromBase64String(payload.EncryptedPayload),
                                                        Convert.FromBase64String(aesKey), Convert.FromBase64String(payload.Iv),
                                                        Convert.FromBase64String("cmFuZG9t"));

                string eventType = string.Empty;

               // var accountInfo = Account.DeserializeAccountData(decryptedPayload, out eventType);

                //Save the decrypted payload information in RPS table.
                //OutBoundDAL outBoundDAL = new OutBoundDAL();
                //outBoundDAL.SaveNotificationPayload(eventType, accountInfo);
               
                return Ok();
            }
            catch(Exception ex)
            {
                return InternalServerError();
            }

        }

    }
}
