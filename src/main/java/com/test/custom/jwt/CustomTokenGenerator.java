package com.test.custom.jwt;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;

import java.util.HashMap;
import java.util.Map;

public class CustomTokenGenerator extends JWTGenerator{
    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext) throws APIManagementException {
        Map<String, String> claims = super.populateStandardClaims(validationContext);
        boolean isApplicationToken = validationContext.getValidationInfoDTO().getUserType().equalsIgnoreCase(APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION) ? true : false;
        String dialect = getDialectURI();
        if (claims.get(dialect + "/enduser") != null) {
            if (isApplicationToken) {
                claims.put(dialect + "/enduser", "null");
                claims.put(dialect + "/enduserTenantId", "null");
            } else {
                String enduser = claims.get(dialect + "/enduser");
                if (enduser.endsWith("@carbon.super")) {
                    enduser = enduser.replace("@carbon.super", "");
                    claims.put(dialect + "/enduser", enduser);
                }
            }
        }

        return claims;

    }

    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext) throws APIManagementException{
        Long time = System.currentTimeMillis();
        String text = "This is custom JWT";
        Map<String,String> customClaims = new HashMap<String, String>();
        customClaims.put("current_timestamp", time.toString());
        customClaims.put("messge" , text);
        customClaims.put(getDialectURI() + "/scope", validationContext.getValidationInfoDTO().getScopes().toString());
        return customClaims;
    }
}

