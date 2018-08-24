using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT.Decode
{
    class Program
    {
        static void Main(string[] args)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            const string jwtInput = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0YWlraG9hbl9sb2FpIjoiMyIsInRhaWtob2FuX2lkIjoiNDI3IiwidGFpa2hvYW5fZW1haWwiOm51bGwsInRhaWtob2FuX3NkdCI6IjA5NjkzNTMwOTAiLCJ0YWlraG9hbl9oaW5oZGFpZGllbiI6bnVsbCwidGFpa2hvYW5fdGVuIjoiVHJhbiBWbyBIb2FpIEFuIiwidGFpa2hvYW5fdHJhbmd0aGFpIjoiNSIsInRhaWtob2FuX3NvZHUiOiIwIiwiZXhwIjoxNTM3NjY1OTM0fQ.HTd7ooBs_15Vt_76qA55bjrlDpK9K4VkWhm9zDpgZkc";

            //Check if readable token (string is in a JWT format)
            var readableToken = jwtHandler.CanReadToken(jwtInput);
            var res = string.Empty;
            if (readableToken)
            {
                var token = jwtHandler.ReadJwtToken(jwtInput);

                //Extract the headers of the JWT
                var headers = token.Header;
                var jwtHeader = "{";
                foreach (var h in headers) jwtHeader += '"' + h.Key + "\":\"" + h.Value + "\",";
                jwtHeader += "}";
                res = "Header:\r\n" + JToken.Parse(jwtHeader).ToString(Formatting.Indented);

                //Extract the payload of the JWT
                var claims = token.Claims;
                var jwtPayload = claims.Aggregate("{", (current, c) => current + ('"' + c.Type + "\":\"" + c.Value + "\","));
                jwtPayload += "}";
                res += "\r\nPayload:\r\n" + JToken.Parse(jwtPayload).ToString(Formatting.Indented);
                Console.WriteLine(res);
            }
        }
    }
}
