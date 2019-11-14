using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace NotificationPayload.Models
{
    public class Account
    {
        public string AccountName { get; set; }
        public string AccountType { get; set; }
        public string AccountNumber { get; set; }
        public string AccountCurrency { get; set; }
        public decimal Amount { get; set; }
        public string TransactionType { get; set; }
        public string OurReference { get; set; }
        public string YourReference { get; set; }

        public string TransactionText { get; set; }
        public string TransactionDateTime { get; set; }
        public string BusinessDate { get; set; }
        public string EffectiveDate { get; set; }
        public string SubAccountIndicator { get; set; }
        public string PayNowIndicator { get; set; }
        public string InstructionId { get; set; }

        public string NotificationId { get; set; }
        public string RemittanceInformation { get; set; }
        public string OriginatorAccountName { get; set; }
        public string TransactionDescription { get; set; }


        public static Account DeserializeAccountData(string AccountDataJson, out string transType)
        {
            JObject obj = JObject.Parse(AccountDataJson);

            //Transatciontype credit / Debit
            transType = (string)obj.SelectToken("event");

            //get account data from json.
            var accountData = obj.SelectToken("data");

            var accountInfo = Newtonsoft.Json.JsonConvert.DeserializeObject<Account>(accountData.ToString());

            return accountInfo;
        }
       

    }
}