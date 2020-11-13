using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthentication.Models
{
    public class User
    {
        [Key]
        public int id { get; set; }
        public string user_name { get; set; }
        public string password { get; set; }
    }

    public class UserDTO
    {
        [Required]
        public string user_name { get; set; }
        [Required]
        public string password { get; set; }
    }
}
