using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace NotificationPayload.Models
{
    public class Payload
    {
        public string EncryptedPayload { get; set; }
        public string EncryptedSessionKey { get; set; }
        public string Iv { get; set; }
        public string PayloadSignature { get; set; }
    }
}