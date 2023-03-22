# Scoring API

 >## Disclaimer: This API is just for studying and is not 'best practise' 

### API to abstract scoring service.
Feature of this API is that users call the methods by sending POST requests.
The method name and request parameters are passed.

Structure of request:

```python
{
    "account": "<some company name>",
    "login": "<username>",
    "method": "<method name>",
    "token": "<authentication token>",
    "arguments": "{<arguments for the method being called>}"
}
```

>- account - str, optional, can be empty
>- ogin - str, necessary, can be empty
>- method - str, necessary, can be empty
>- token -str, necessary, can be empty
>- arguments - dict(json object), necessary, can be empty


### Validation
The request is valid if all its fields are valid.

### Response structure
OK:
```python
{
    "code": "<response code>",
    "response": "{<response body>}"
}
```

ERROR:
```python
{
    "code": "<response code>",
    "error": "{<error message>}"
}
```