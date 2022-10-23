using ECOM.Producto.Prueba.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ECOM.Producto.Prueba.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly IJWTAuthManager _authentication;

        public LoginController(IJWTAuthManager authentication)
        {
            _authentication = authentication;
        }


        [HttpPost, Route("login")]
        public IActionResult Login(LoginDTO loginDTO)
        {
            string token = "";
            try
            {
                if (string.IsNullOrEmpty(loginDTO.UserName) ||
                string.IsNullOrEmpty(loginDTO.Password))
                    return BadRequest("Username and/or Password not specified");

                if (loginDTO.UserName.Equals("miguel") &&
                loginDTO.Password.Equals("123"))
                {
                    token = _authentication.GenerateJWT(new LoginDTO() { UserName= "miguel",Password = "jimenez" });
                    return Ok(token);
                }
            }
            catch
            {
                return BadRequest
                ("An error occurred in generating the token");
            }
            return Ok(token);
        }
    }

}
