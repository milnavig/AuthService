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
# Register the user

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

## Examples of usage (GraphQL)