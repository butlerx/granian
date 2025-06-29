import base64
import hashlib
import hmac
from typing import Optional, Tuple, Union


class BasicAuth:
    """Basic HTTP authentication handler."""
    
    def __init__(self, username: str, password: str, realm: str = "Granian"):
        """
        Initialize basic authentication.
        
        Args:
            username: The expected username
            password: The expected password
            realm: The authentication realm (shown in browser prompt)
        """
        self.username = username
        self.password = password
        self.realm = realm
    
    def validate_credentials(self, auth_header: Optional[str]) -> bool:
        """
        Validate the Authorization header.
        
        Args:
            auth_header: The Authorization header value
            
        Returns:
            True if credentials are valid, False otherwise
        """
        if not auth_header:
            return False
            
        if not auth_header.startswith('Basic '):
            return False
            
        try:
            # Extract and decode the credentials
            encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            
            # Split username and password
            if ':' not in decoded_credentials:
                return False
                
            username, password = decoded_credentials.split(':', 1)
            
            # Compare with expected credentials
            return username == self.username and password == self.password
            
        except (ValueError, UnicodeDecodeError):
            return False
    
    def get_unauthorized_response_headers(self) -> dict:
        """
        Get headers for 401 Unauthorized response.
        
        Returns:
            Dictionary with WWW-Authenticate header
        """
        return {
            'WWW-Authenticate': f'Basic realm="{self.realm}"'
        }


class HtpasswdAuth:
    """HTTP Basic Authentication using .htpasswd file format."""
    
    def __init__(self, htpasswd_file: str, realm: str = "Granian"):
        """
        Initialize htpasswd authentication.
        
        Args:
            htpasswd_file: Path to .htpasswd file
            realm: The authentication realm (shown in browser prompt)
        """
        self.htpasswd_file = htpasswd_file
        self.realm = realm
        self._credentials = self._load_credentials()
    
    def _load_credentials(self) -> dict:
        """Load credentials from .htpasswd file."""
        credentials = {}
        try:
            with open(self.htpasswd_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            username, password_hash = line.split(':', 1)
                            credentials[username] = password_hash
        except FileNotFoundError:
            raise FileNotFoundError(f"htpasswd file not found: {self.htpasswd_file}")
        except Exception as e:
            raise ValueError(f"Error reading htpasswd file: {e}")
        
        return credentials
    
    def validate_credentials(self, auth_header: Optional[str]) -> bool:
        """
        Validate the Authorization header against .htpasswd file.
        
        Args:
            auth_header: The Authorization header value
            
        Returns:
            True if credentials are valid, False otherwise
        """
        if not auth_header:
            return False
            
        if not auth_header.startswith('Basic '):
            return False
            
        try:
            # Extract and decode the credentials
            encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            
            # Split username and password
            if ':' not in decoded_credentials:
                return False
                
            username, password = decoded_credentials.split(':', 1)
            
            # Check if username exists and validate password
            if username not in self._credentials:
                return False
                
            stored_hash = self._credentials[username]
            return self._verify_password(password, stored_hash)
            
        except (ValueError, UnicodeDecodeError):
            return False
    
    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash.
        
        Supports Apache htpasswd formats:
        - MD5 (apr1)
        - SHA1
        - bcrypt
        - plain text (not recommended)
        """
        if stored_hash.startswith('$apr1$'):
            return self._verify_apr1(password, stored_hash)
        elif stored_hash.startswith('{SHA}'):
            return self._verify_sha1(password, stored_hash)
        elif stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$'):
            return self._verify_bcrypt(password, stored_hash)
        else:
            # Plain text (not recommended for production)
            return password == stored_hash
    
    def _verify_apr1(self, password: str, stored_hash: str) -> bool:
        """Verify APR1/MD5 password hash."""
        try:
            import crypt  # type: ignore
            return crypt.crypt(password, stored_hash) == stored_hash
        except ImportError:
            # Fallback implementation for systems without crypt module
            return self._verify_apr1_fallback(password, stored_hash)
    
    def _verify_apr1_fallback(self, password: str, stored_hash: str) -> bool:
        """Fallback APR1 verification without crypt module."""
        # This is a simplified implementation
        # In production, you should use the crypt module or a proper library
        parts = stored_hash.split('$')
        if len(parts) != 4:
            return False
        
        salt = parts[2]
        expected_hash = parts[3]
        
        # Simple MD5 implementation (this is not the full APR1 algorithm)
        # For production use, consider using a proper library like passlib
        md5_hash = hashlib.md5((password + salt).encode()).hexdigest()
        return md5_hash == expected_hash
    
    def _verify_sha1(self, password: str, stored_hash: str) -> bool:
        """Verify SHA1 password hash."""
        if not stored_hash.startswith('{SHA}'):
            return False
        
        expected_hash = stored_hash[5:]  # Remove {SHA} prefix
        actual_hash = base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
        return actual_hash == expected_hash
    
    def _verify_bcrypt(self, password: str, stored_hash: str) -> bool:
        """Verify bcrypt password hash."""
        try:
            import bcrypt  # type: ignore
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except ImportError:
            # bcrypt not available, return False
            return False
    
    def get_unauthorized_response_headers(self) -> dict:
        """
        Get headers for 401 Unauthorized response.
        
        Returns:
            Dictionary with WWW-Authenticate header
        """
        return {
            'WWW-Authenticate': f'Basic realm="{self.realm}"'
        }


def create_auth_handler(auth_type: str, **kwargs) -> Optional[Union[BasicAuth, HtpasswdAuth]]:
    """
    Create an authentication handler based on type.
    
    Args:
        auth_type: Type of authentication ('basic' or 'htpasswd')
        **kwargs: Additional arguments for the auth handler
        
    Returns:
        Authentication handler instance or None if disabled
    """
    if not auth_type or auth_type.lower() == 'none':
        return None
    
    auth_type = auth_type.lower()
    
    if auth_type == 'basic':
        username = kwargs.get('username')
        password = kwargs.get('password')
        realm = kwargs.get('realm', 'Granian')
        
        if not username or not password:
            raise ValueError("Username and password are required for basic authentication")
        
        return BasicAuth(username, password, realm)
    
    elif auth_type == 'htpasswd':
        htpasswd_file = kwargs.get('htpasswd_file')
        realm = kwargs.get('realm', 'Granian')
        
        if not htpasswd_file:
            raise ValueError("htpasswd_file is required for htpasswd authentication")
        
        return HtpasswdAuth(htpasswd_file, realm)
    
    else:
        raise ValueError(f"Unsupported authentication type: {auth_type}")


def extract_auth_header(headers: dict) -> Optional[str]:
    """
    Extract Authorization header from request headers.
    
    Args:
        headers: Request headers dictionary
        
    Returns:
        Authorization header value or None
    """
    # Check various possible header names
    auth_header_names = ['authorization', 'Authorization', 'HTTP_AUTHORIZATION']
    
    for header_name in auth_header_names:
        if header_name in headers:
            return headers[header_name]
    
    return None 