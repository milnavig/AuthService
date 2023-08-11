# AuthService

## How to install

```
npm i
```

*** Set your DB_HOST, DB_PORT and DB_NAME in the .env file! ***

```
npm run dev
```

## Examples of usage (REST API)
### Register the new user

Endpoint:
```
POST http://0.0.0.0:5000/api/user/register
```

Request body format: JSON

Example of the body:

```
{
    "email": "test4@gmail.com", 
    "password": "1234a"
}
```

Example of response:
```
{
    "message": "User was created successfully! User id: 64d67775942d1b7c5ddcbbe9"
}
```

### First step of two-factor authorization (returns QR-code)

Endpoint:
```
POST http://0.0.0.0:5000/api/user/enable-2fa
```

Request body format: JSON

Example of the body:

```
{
    "email": "test4@gmail.com", 
    "password": "1234a"
}
```

Example of response:
```
{
    "userId": "64d67775942d1b7c5ddcbbe9",
    "qrcodeUrl": "data:image/png;base64,iVBORw0KGg..."
}
```

### Second step of two-factor authorization (returns JWT tokens)

Endpoint:
```
POST http://0.0.0.0:5000/api/user/login-2fa
```

Request body format: JSON

Example of the body:

```
{
    "userId": "64d67775942d1b7c5ddcbbe9",
    "otpAuthUrl": "otpauth://totp/AuthService?secret=IBNVE6DFM5JGE3RMLVUX2KKJOVFUU5D5&issuer=AuthService"
}
```

Example of response:
```
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3Nzg3NTQsImV4cCI6MTY5MTc4MDU1NH0.HcchzIcDPblOOd5CEt7IiBVy4g2TQshXVgFoWQYpWl4",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3Nzg3NTQsImV4cCI6MTY5MTg2NTE1NH0.toHsvstgkwg97bCdtfDS4iRImtjxldT-iZYFobVhhCg"
}
```

### Update password

Endpoint:
```
POST http://0.0.0.0:5000/api/user/update
```

Request body format: JSON

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3Nzg3NTQsImV4cCI6MTY5MTc4MDU1NH0.HcchzIcDPblOOd5CEt7IiBVy4g2TQshXVgFoWQYpWl4
```

Example of the body:

```
{
    "old_password": "1234a", 
    "new_password": "1234b"
}
```

Example of response:
```
{
    "message": "Password changed successfully"
}
```

### Refresh JWT tokens

Endpoint:
```
GET http://0.0.0.0:5000/api/user/refresh
```

Request body format: JSON

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3Nzg3NTQsImV4cCI6MTY5MTc4MDU1NH0.HcchzIcDPblOOd5CEt7IiBVy4g2TQshXVgFoWQYpWl4
```

Example of response:
```
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3NzkyMjQsImV4cCI6MTY5MTc4MTAyNH0.VQhL5qS5PS7kceMUwRqKhM7Hn23c4-ben06LrPvaeKk",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3NzkyMjQsImV4cCI6MTY5MTg2NTYyNH0.TRgXM_GnNvGwimX_XFV08wn--5NfElSLj--XhDeQh1k"
}
```

### Logout

Endpoint:
```
POST http://0.0.0.0:5000/api/user/logout
```

Request body format: JSON

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2Nzc3NTk0MmQxYjdjNWRkY2JiZTkiLCJpYXQiOjE2OTE3Nzg3NTQsImV4cCI6MTY5MTc4MDU1NH0.HcchzIcDPblOOd5CEt7IiBVy4g2TQshXVgFoWQYpWl4
```

Example of response:
```
{
    "message": "User was logged out!"
}
```

## Examples of usage (GraphQL)

**GraphQL endpoint**: POST http://0.0.0.0:5000/graphql

### Register the new user

Example of the query:

```
mutation Register($input: UserInput!) {
  register(input: $input) {
    message
  }
}
```
Example of GraphQL variables: 
```
{
  "input": {
    "email": "test5@gmail.com",
    "password": "1234a"
  }
}
```
Example of response:
```
{
    "data": {
        "register": {
            "message": "User was created successfully! User id: 64d682e4ea1f34db9c09b7e0"
        }
    }
}
```

### First step of two-factor authorization (returns QR-code)

Example of the query:

```
mutation Enable2FA($input: UserInput!) {
  enable_2fa(input: $input) {
    userId
    qrcodeUrl
  }
}
```
Example of GraphQL variables: 
```
{
  "input": {
    "email": "test5@gmail.com",
    "password": "1234a"
  }
}
```
Example of response:
```
{
    "data": {
        "enable_2fa": {
            "userId": "64d682e4ea1f34db9c09b7e0",
            "qrcodeUrl": "data:image/png;base64,iVBORw0KGg..."
        }
    }
}
```

### Second step of two-factor authorization (returns JWT tokens)

Example of the query:

```
mutation Login2FA($input: CodeInput!) {
  login_2fa(input: $input) {
    access_token
    refresh_token
  }
}
```
Example of GraphQL variables: 
```
{
  "input": {
    "userId": "64d682e4ea1f34db9c09b7e0",
    "otpAuthUrl": "otpauth://totp/AuthService?secret=NV6WQVDVJZMEWWCPMVKHOY2RKMYDQTJJ&issuer=AuthService"
  }
}
```
Example of response:
```
{
    "data": {
        "login_2fa": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODAxOTMsImV4cCI6MTY5MTc4MTk5M30.foMWM90fe3KHB9RzP-3XYGjm7jDjhHGXRRDK0qS26qs",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODAxOTMsImV4cCI6MTY5MTg2NjU5M30.1cvC1wvPRZQD98hCY8dm38MsjaQstGXkKUyH1OH1KD0"
        }
    }
}
```

### Update password

Example of the query:

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODAxOTMsImV4cCI6MTY5MTc4MTk5M30.foMWM90fe3KHB9RzP-3XYGjm7jDjhHGXRRDK0qS26qs
```

```
mutation Update($input: UpdateInput!) {
  update(input: $input) {
    message
  }
}
```
Example of GraphQL variables: 
```
{
  "input": {
    "old_password": "1234a",
    "new_password": "1234b"
  }
}
```
Example of response:
```
{
    "data": {
        "update": {
            "message": "Password changed successfully"
        }
    }
}
```

### Refresh JWT tokens

Example of the query:

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODAxOTMsImV4cCI6MTY5MTc4MTk5M30.foMWM90fe3KHB9RzP-3XYGjm7jDjhHGXRRDK0qS26qs
```

```
query Refresh {
  refresh {
    access_token
    refresh_token
  }
}
```

Example of response:
```
{
    "data": {
        "refresh": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODA2MTQsImV4cCI6MTY5MTc4MjQxNH0.-yMNj6TX49Zi-3U6SM2noxrjewJTEEr6nl4ryNS-524",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODA2MTQsImV4cCI6MTY5MTg2NzAxNH0.Tp0TDsfuzkbesg21aUc-4Yyho31QBK1U9VBXboWx3pw"
        }
    }
}
```

### Logout

Example of the query:

Add request header **Authorization** with value:

```
Bearer insert_access_token
```

For example:

```
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NGQ2ODJlNGVhMWYzNGRiOWMwOWI3ZTAiLCJpYXQiOjE2OTE3ODAxOTMsImV4cCI6MTY5MTc4MTk5M30.foMWM90fe3KHB9RzP-3XYGjm7jDjhHGXRRDK0qS26qs
```

```
query Logout {
  logout {
    message
  }
}
```

Example of response:
```
{
    "data": {
        "logout": {
            "message": "User was logged out!"
        }
    }
}
```