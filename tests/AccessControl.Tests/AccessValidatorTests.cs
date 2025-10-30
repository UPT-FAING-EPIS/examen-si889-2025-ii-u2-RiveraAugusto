using Xunit;
using AccessControl;

namespace AccessControl.Tests
{
    public class AccessValidatorTests
    {
        [Fact]
        public void Should_Validate_Correct_Request()
        {
            var validator = new AccessValidator(); // Admin + 192.168.1.100 por defecto
            var request = new AccessRequest
            {
                Username = "admin",
                Role = "Admin",
                IpAddress = "192.168.1.100"
            };

            Assert.True(validator.Validate(request));
        }

        [Fact]
        public void Should_Reject_Request_With_Invalid_Role()
        {
            var validator = new AccessValidator();
            var request = new AccessRequest
            {
                Username = "user",
                Role = "User",
                IpAddress = "192.168.1.100"
            };

            Assert.False(validator.Validate(request));
        }

        [Fact]
        public void Should_Reject_Request_With_Invalid_Ip()
        {
            var validator = new AccessValidator();
            var request = new AccessRequest
            {
                Username = "admin",
                Role = "Admin",
                IpAddress = "10.0.0.1"
            };

            Assert.False(validator.Validate(request));
        }
    }
}