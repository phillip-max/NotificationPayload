namespace NotificationPayload.Models
{
    public class Payload
    {
        public string EncryptedPayload { get; set; }
        public string EncryptedSessionKey { get; set; }
        public string Iv { get; set; }
        public string PayloadSignature { get; set; }

        public string Error { get; set; }
    }
}