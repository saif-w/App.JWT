using JWT.ASP.App.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.ASP.App.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IConfiguration _config;
        public UsersController(IConfiguration configration)
        {
            _config= configration;
        }

        private User LoginAuth(User user)
        {
            User _user=null;
            if(user.UserName == "saif"&& user.Password=="123")
            {
                _user = new User { UserName = "saif walid",Password="123" };
            }
            return _user;
        }

        private string TokenGenrate(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                null,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(User user)
        {
            IActionResult responce = Unauthorized();
            var user_=LoginAuth(user);
            if(user_!=null)
            {
                var token = TokenGenrate(user_);
                responce = Ok(new { token = token });

            }
            return responce;
        }
    
    }
}
