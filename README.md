## Signature CSC service

Signature CSC (Cloud Signature Consortium) service is a service that:  
- Takes a PDF as input  
- Generates the PDF hash  
- Sends the hash to be sign to a Remote Signing Service Provider (RSSP) through CSC APIs  
- Inserts the signature to the PDF  
- Returns the signed PDF   

This sample code shows how CSC calls can be made: see SignatureService.java.  

## Prerequisites

- JDK 12  
- Maven 3  

## Compilation

`$ mvn clean install`

## Execution
  
`$ java -jar signature-csc-service-web-[VERSION].jar -f application.properties` 

## Documentation

Solution architecture is available here: http://www.bntan.com/medium-architecting-a-csc-signature-solution  
API documentation is available here: http://localhost:8080/bntan/service  

## URL

Signature service URL: http://localhost:8080/bntan/service/signPDF
