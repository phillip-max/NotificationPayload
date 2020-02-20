using Newtonsoft.Json.Linq;

namespace NotificationPayload.Models
{
    public class Transaction
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


        public static Transaction DeserializeAccountData(string TransactionDataJson, out string transType)
        {
            JObject obj = JObject.Parse(TransactionDataJson);

            //Transatciontype credit / Debit
            transType =(string)obj.SelectToken("event");

            

            //get account data from json.
            var transactionData = obj.SelectToken("data");

            var transactionInfo = Newtonsoft.Json.JsonConvert.DeserializeObject<Transaction>(transactionData.ToString());

            return transactionInfo;
        }

        public static string GetFormattedAccNo(string transctionText)
        {
            return (transctionText.Replace(" ", string.Empty)).Trim();
        }

    }
}