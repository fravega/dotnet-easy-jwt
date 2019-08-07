namespace EasyJWT
{
	/// <summary>
	/// Contains a set of parameters that will be used to build the Microsoft.IdentityModel.Tokens.TokenValidationParameters
	/// </summary>
	public class ValidationParameters
    {
		/// <summary>
		/// If set, issuer will be validated providing this value
		/// </summary>
        public string ValidIssuer { get; set; }

		/// <summary>
		/// If set, audience will be validated providing this value
		/// </summary>
		public string ValidAudience { get; set; }

		/// <summary>
		/// If lifetime should be validated
		/// </summary>
		public bool ValidateLifetime { get; set; }

		public static ValidationParameters Default(string issuer) => new ValidationParameters { ValidIssuer = issuer, ValidateLifetime = true };
    }
}