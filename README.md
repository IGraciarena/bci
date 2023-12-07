# bci

### To run the application you would need:
- **openjdk** **11.0.18** 2023-01-17 LTS OpenJDK Runtime Environment Corretto-11.0.18.10.1 (build 11.0.18+10-LTS) OpenJDK 64-Bit
  Server VM Corretto-11.0.18.10.1 (build 11.0.18+10-LTS, mixed mode)
- **Gradle** 7.5.1
- **Postman** or **cURL** (optional)

### POSTMAN COLLECTION
- [Postman Collection](./collection)

### DIAGRAMS
- [Secuence Diagram sign-up and log-in and Component diagram](./diagram)
- [Flow Diagram](https://drive.google.com/file/d/1kbKlYjT-H06_dYpPOwKfSzYlESHbEWAO/view?usp=sharing)

### API DOCUMENTATION
#### **[POST]** localhost:8080/api/sign-up
- **body:** 
```
{ 
    "name":"String",
    "email":"String",
    "password":"String",
    "phones": [{ 
                "number":"Integer",
                "cityCode":"Long",
                "countryCode":"String" 
               }]
}
```
- **response**:
```
{ 
    "id":"UUID",
    "created":"Instant",
    "lastLogin":"Instant",
    "token":"Bearer JWT"
    "isActive":"boolean"
}
```

#### **[ POST ]** localhost:8080/api/log-in
- **body:** 
```
     {
        "email":"String",
        "password":"String"
     }
```
- **response**:
    
```
    {
      "id": "UUID",
      "created": "Instant",
      "lastLogin": "Instant",
      "token": "Bearer JWT",
      "isActive": "boolean",
      "name": "String",
      "email": "String",
      "password": "String",
      "phones": [{
          "number": "Integer",
          "cityCode": "Long",
          "countryCode": "String"
       }]
    }
```

### Configurations
1. You would probably don't have the need to use any configuration
    - H2 database is set to it's defaults parameters.
    - access to the H2 ui is disabled by security url.
2. To check out the UI (**swagger**) API you can access with your credentials.
   - URL: http://localhost:8080/swagger-ui/index.html
     - once you sign in
     - provide an email and password.
     - JWT Token it's not necessary.
       

