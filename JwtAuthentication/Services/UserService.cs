using JwtAuthentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication.Services
{
    public interface IUserService
    {
        User Authenticate(string user_name, string password);
        User GetById(int id);
        Task<string> encryptPassword(string password);
    }

    public class UserService : IUserService
    {
        private ApplicationDbContext _context;

        public UserService(ApplicationDbContext context)
        {
            _context = context;
        }

        public User Authenticate(string user_name, string password)
        {
            if (string.IsNullOrEmpty(user_name) || string.IsNullOrEmpty(password))
                return null;
            string hashPassword = PasswordMd5(password);
            var user = _context.Users.SingleOrDefault(x => x.user_name == user_name && x.password == hashPassword);

            // check if username not exists
            if (user == null)
                return null;

            // authentication successful
            return user;
        }

        public User GetById(int id)
        {
            return _context.Users.Find(id);
        }
        private static string PasswordMd5(string password)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                var result = sb.ToString();
                return result.ToLower();
            }
        }

        public async Task<string> encryptPassword(string password)
        {
            return PasswordMd5(password);
        }
    }
}
