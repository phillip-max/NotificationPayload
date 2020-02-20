using System;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;

namespace NotificationPayload.Models.DAL
{
    public class OutBoundDAL
    {

        /// <summary>
        /// Save the UOB triggerd request to "Tb_UOB_RequestLog" Table.
        /// </summary>
        /// <param name="payload">PayloadData</param>
        public void SavePayloadRequest(string payload)
        {
            String strConnString = ConfigurationManager.ConnectionStrings["connectionRPS"].ConnectionString;
            SqlConnection con = new SqlConnection(strConnString);
            try
            {                
                SqlCommand cmd = new SqlCommand()
                {
                    CommandType = CommandType.StoredProcedure,
                    CommandText = "dbo.Usp_UOB_PayNowRequestDataInsert"
                };
                cmd.Parameters.Add("@PayloadData", SqlDbType.NVarChar).Value = payload;
                cmd.Parameters.Add("@InsertTime", SqlDbType.DateTime).Value = DateTime.Parse(DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture));
                cmd.Parameters.Add("@IsProcessed", SqlDbType.Bit).Value = true;
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

        /// <summary>
        /// Save the decrypted UOB account and transaction to "Tb_UOB_Notification" table.
        /// </summary>
        /// <param name="eventType">Transactiontyep(Credit or Debit)</param>
        /// <param name="account">Decrypted transaction details</param>
        public void SaveNotificationPayload(string eventType, Transaction account)
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

                cmd.Parameters.Add("@TransactionDateTime", SqlDbType.DateTime).Value = string.IsNullOrEmpty(account.TransactionDateTime) ? DateTime.Parse(DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture))
                                                                                   :DateTime.Parse(DateTime.ParseExact(account.TransactionDateTime, "dd-MM-yyyy HH:mm:ss", CultureInfo.InvariantCulture).ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture)); ;

                cmd.Parameters.Add("@TransactionDescription", SqlDbType.NVarChar).Value = account.TransactionDescription ?? string.Empty;
                cmd.Parameters.Add("@TransactionText", SqlDbType.NVarChar).Value = string.IsNullOrEmpty(account.TransactionText) ? string.Empty :
                                                                                 (account.TransactionText.Replace(" ", string.Empty)).Trim();
                cmd.Parameters.Add("@TransactionType", SqlDbType.NVarChar).Value = account.TransactionType ?? string.Empty;
                cmd.Parameters.Add("@YourReference", SqlDbType.NVarChar).Value = account.YourReference ?? string.Empty;
                cmd.Parameters.Add("@OriginalAccNo", SqlDbType.NVarChar).Value = account.TransactionText ?? string.Empty;

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