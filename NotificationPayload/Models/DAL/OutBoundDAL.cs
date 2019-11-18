using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Web;

namespace NotificationPayload.Models.DAL
{
    public class OutBoundDAL
    {
        public void SaveNotificationPayload(string eventType, Account account)
        {
            String strConnString = ConfigurationManager.ConnectionStrings["connectionRPS"].ConnectionString;
            SqlConnection con = new SqlConnection(strConnString);
            try
            {                
                SqlCommand cmd = new SqlCommand()
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandText = "dbo.Usp_UOB_PayNowInsert"
                };
                cmd.Parameters.Add("@EventType", SqlDbType.NVarChar).Value = eventType ?? string.Empty;
                cmd.Parameters.Add("@AccountName", SqlDbType.NVarChar).Value = account.AccountName ?? string.Empty;
                cmd.Parameters.Add("@AccountNumber", SqlDbType.NVarChar).Value = account.AccountNumber ?? string.Empty;
                cmd.Parameters.Add("@AccountCurrency", SqlDbType.NVarChar).Value = account.AccountCurrency ?? string.Empty;
                cmd.Parameters.Add("@AccountType", SqlDbType.NVarChar, 1).Value = account.AccountType ?? string.Empty;
                cmd.Parameters.Add("@Amount", SqlDbType.Decimal).Value = account.Amount;
                cmd.Parameters.Add("@BusinessDate", SqlDbType.NVarChar).Value = account.BusinessDate ?? string.Empty;
                cmd.Parameters.Add("@EffectiveDate", SqlDbType.NVarChar).Value = account.EffectiveDate ?? string.Empty;
                cmd.Parameters.Add("@InstructionId", SqlDbType.NVarChar).Value = account.InstructionId ?? string.Empty;
                cmd.Parameters.Add("@NotificationId", SqlDbType.NVarChar).Value = account.NotificationId ?? string.Empty;
                cmd.Parameters.Add("@OriginatorAccountName", SqlDbType.NVarChar).Value = account.OriginatorAccountName ?? string.Empty;
                cmd.Parameters.Add("@OurReference", SqlDbType.NVarChar).Value = account.OurReference ?? string.Empty;
                cmd.Parameters.Add("@PayNowIndicator", SqlDbType.NVarChar).Value = account.PayNowIndicator ?? string.Empty;
                cmd.Parameters.Add("@RemittanceInformation", SqlDbType.NVarChar).Value = account.RemittanceInformation ?? string.Empty;
                cmd.Parameters.Add("@SubAccountIndicator", SqlDbType.NVarChar).Value = account.SubAccountIndicator ?? string.Empty;
                cmd.Parameters.Add("@TransactionDateTime", SqlDbType.NVarChar).Value = account.TransactionDateTime ?? string.Empty;
                cmd.Parameters.Add("@TransactionDescription", SqlDbType.NVarChar).Value = account.TransactionDescription ?? string.Empty;
                cmd.Parameters.Add("@TransactionText", SqlDbType.NVarChar).Value = account.TransactionText ?? string.Empty;
                cmd.Parameters.Add("@TransactionType", SqlDbType.NVarChar).Value = account.TransactionType ?? string.Empty;
                cmd.Parameters.Add("@YourReference", SqlDbType.NVarChar).Value = account.YourReference ?? string.Empty;

                cmd.Connection = con;
                con.Open();
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                con.Close();
                con.Dispose();
            }
        }
    }
}