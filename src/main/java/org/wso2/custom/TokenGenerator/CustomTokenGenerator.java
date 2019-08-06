package org.wso2.custom.TokenGenerator;


import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;
import org.wso2.carbon.apimgt.api.*;
import org.wso2.carbon.apimgt.impl.token.ClaimsRetriever;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import java.util.HashMap;
import java.util.Map;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import java.util.Set;

public class CustomTokenGenerator extends JWTGenerator {

    ApiMgtDAO apiMgtDAO = ApiMgtDAO.getInstance();

    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext) throws APIManagementException {
        // Get claim dialect
        String dialect;
        ClaimsRetriever claimsRetriever = getClaimsRetriever();
        if (claimsRetriever != null) {
            dialect = claimsRetriever.getDialectURI(validationContext.getValidationInfoDTO().getEndUserName());
        } else {
            dialect = getDialectURI();
        }
        // Get default claims from super
        Map<String, String> claims = super.populateStandardClaims(validationContext);
//        Get token type
//        boolean isApplicationToken = validationContext.getValidationInfoDTO().getUserType().equalsIgnoreCase(APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION);
        return claims;

    }

    @Override
    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext) throws APIManagementException {
        Map<String, String> customClaims = super.populateCustomClaims(validationContext);
        if (customClaims == null){
            customClaims = new HashMap<String, String>();
        }
        HashMap<String, String> apiscope=new HashMap<String, String>();
        Set<Scope> scopes= apiMgtDAO.getAPIScopes(new APIIdentifier( validationContext.getValidationInfoDTO().getApiPublisher(),validationContext.getValidationInfoDTO().getApiName(),validationContext.getVersion()));
        for (Scope scope : scopes) {
            apiscope.put(scope.getKey(),scope.getRoles());
        }
        if(!apiscope.isEmpty()) {
            customClaims.put(getDialectURI() + "/scopesRoles", apiscope.toString());
        }
        return customClaims;
    }

}
