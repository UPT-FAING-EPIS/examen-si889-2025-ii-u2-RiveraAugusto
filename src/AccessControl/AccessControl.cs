namespace AccessControl
{
    public class AccessRequest
    {
        public string Username { get; set; }
        public string Role { get; set; }
        public string IpAddress { get; set; }
    }

    // Handler base del Chain of Responsibility
    public abstract class AccessHandler
    {
        private AccessHandler _next;

        public AccessHandler SetNext(AccessHandler next)
        {
            _next = next;
            return next;
        }

        public bool Handle(AccessRequest request)
        {
            if (!Check(request))
                return false;

            return _next == null ? true : _next.Handle(request);
        }

        protected abstract bool Check(AccessRequest request);
    }

    public class UsernameHandler : AccessHandler
    {
        protected override bool Check(AccessRequest request)
        {
            return !string.IsNullOrEmpty(request.Username);
        }
    }

    public class RoleHandler : AccessHandler
    {
        private readonly string _requiredRole;

        public RoleHandler(string requiredRole = "Admin")
        {
            _requiredRole = requiredRole;
        }

        protected override bool Check(AccessRequest request)
        {
            return request.Role == _requiredRole;
        }
    }

    public class IpAddressHandler : AccessHandler
    {
        private readonly string _allowedIp;

        public IpAddressHandler(string allowedIp)
        {
            _allowedIp = allowedIp;
        }

        protected override bool Check(AccessRequest request)
        {
            return request.IpAddress == _allowedIp;
        }
    }

    public class AccessValidator
    {
        private readonly AccessHandler _chain;

        // Permite configurar el rol requerido y la IP permitida si fuese necesario
        public AccessValidator(string requiredRole = "Admin", string allowedIp = "192.168.1.100")
        {
            var username = new UsernameHandler();
            var role = new RoleHandler(requiredRole);
            var ip = new IpAddressHandler(allowedIp);

            username.SetNext(role).SetNext(ip);
            _chain = username;
        }

        public bool Validate(AccessRequest request)
        {
            return _chain.Handle(request);
        }
    }
}