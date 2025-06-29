# HTTP Basic Authentication

Granian supports HTTP Basic Authentication to protect your applications. This
feature allows you to require username and password authentication for all HTTP
requests to your application.

## Features

- **Basic Authentication**: Simple username/password authentication
- **Htpasswd Support**: Use Apache-style .htpasswd files
- **Multiple Hash Formats**: Supports MD5, SHA1, bcrypt, and plain text
  passwords

## Command Line Usage

### Basic Authentication

Enable basic authentication with a username and password:

```bash
granian myapp:app --auth-type basic --auth-username admin --auth-password secret
```

### Htpasswd Authentication

Use an Apache-style .htpasswd file:

```bash
granian myapp:app --auth-type htpasswd --auth-htpasswd-file .htpasswd
```

### Custom Realm

Set a custom authentication realm (shown in browser prompts):

```bash
granian myapp:app --auth-type basic --auth-username admin --auth-password secret --auth-realm "My Protected App"
```

### No Authentication (Default)

By default, no authentication is required:

```bash
granian myapp:app
```

## Htpasswd File Format

The .htpasswd file should contain one user per line in the format:

```
username:password_hash
```

### Supported Hash Formats

1. **MD5 (apr1)**: `$apr1$salt$hash`
2. **SHA1**: `{SHA}base64_encoded_hash`
3. **bcrypt**: `$2a$...`, `$2b$...`, `$2y$...`
4. **Plain text**: `password` (not recommended for production)

### Creating Htpasswd Files

You can create .htpasswd files using Apache's htpasswd utility:

```bash
# Create new file with user
htpasswd -c .htpasswd admin

# Add additional users
htpasswd .htpasswd user2
```

Or using Python with the `passlib` library:

```python
from passlib.apache import HtpasswdFile

# Create new file
ht = HtpasswdFile(".htpasswd", new=True)
ht.set_password("admin", "secret")
ht.save()

# Add more users
ht.set_password("user2", "password2")
ht.save()
```

## API Reference

### CLI Options

- `--auth-type`: Authentication type (`none`, `basic`, `htpasswd`)
- `--auth-username`: Username for basic authentication
- `--auth-password`: Password for basic authentication
- `--auth-realm`: Authentication realm (default: "Granian")
- `--auth-htpasswd-file`: Path to .htpasswd file
