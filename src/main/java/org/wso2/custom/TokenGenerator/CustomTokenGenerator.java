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
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

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
        return claims;

    }

    @Override
    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext) throws APIManagementException {
        Map<String, String> customClaims = super.populateCustomClaims(validationContext);
        if (customClaims == null){
            customClaims = new HashMap<String, String>();
        }
        Set<Scope> scopes= apiMgtDAO.getAPIScopes(new APIIdentifier( validationContext.getValidationInfoDTO().getApiPublisher(),validationContext.getValidationInfoDTO().getApiName(),validationContext.getVersion()));
        JSONObject scoperole = new JSONObject();
        for (Scope scope : scopes) {
            JSONArray roles = new JSONArray();
            roles.add(scope.getRoles());
            scoperole.put(scope.getKey(),roles);
        }
        if(!scoperole.isEmpty()) {
            customClaims.put(getDialectURI() + "/scopesroles", scoperole.toJSONString());
        }
        return customClaims;
    }

}
