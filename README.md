# CustomJWTGenerator
Custom JWT Generator
1. Build this project using maven (mvn clean install)

2. After building this project take the jar file inside the target directory and place it inside the <API-M_HOME>/repository/components/lib directory.

3. Add the class in the <JWTGeneratorImpl> element of the <API-M_HOME>/repository/conf/api-manager.xml file

  <JWTConfiguration>
   ....
   <JWTGeneratorImpl>org.wso2.carbon.test.CustomTokenGenerator</JWTGeneratorImpl>
   ....
 </JWTConfiguration>


4. Set the <EnableJWTGeneration> element to true in the <API-M_HOME>/repository/conf/api-manager.xml file.

5. Finally restart the server.

