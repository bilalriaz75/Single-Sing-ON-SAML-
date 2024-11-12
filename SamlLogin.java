package com.tcm.framework.sos;
import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.saml.saml2.core.AuthnRequest;

//import com.tcm.framework.service.Resources;

@WebServlet(name = "SamlLogin", urlPatterns =
{ "/saml/login" })
public class SamlLogin extends HttpServlet {
   protected Logger logger = Logger.getLogger(this.getClass());
   private static final long serialVersionUID = -3146269631698228546L;
   private SamlLogingService samlLoginService = new SamlLogingService();

   protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      String redirectUrl = this.initiateSamlLogin(req, resp);
      resp.getWriter().write(redirectUrl);
   }

   protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      String redirectUrl = this.initiateSamlLogin(req, resp);
      resp.getWriter().write(redirectUrl);
   }

   public String initiateSamlLogin(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
      try {
    	  
    	  String tenantId = "8b86a65e-3c3a-4406-8ac3-19a6b5cc52bc";
          String issuerValue = "AuditDigitizationPRD";
          String assertionConsumerServiceURL = "https://pmida.rtdtradetracker.com/";
    	  
    	  
//    	  String tenantId = "8b86a65e-3c3a-4406-8ac3-19a6b5cc52bc";
//          String issuerValue ="AuditDigitizationPRD";
//          String assertionConsumerServiceURL = "https://pmida.rtdtradetracker.com/";



//         String tenantId = "b4f1578a-47f9-4430-ada2-bb11543569b2";
//        String issuerValue ="AuditDigitizationPRD";
//        String assertionConsumerServiceURL = "https://1ae3-182-180-173-242.ngrok-free.app/CE/";
        logger.info("tenantID: "+tenantId+" issuervalue: "+issuerValue+"  assertionConsumerServiceURL: "+assertionConsumerServiceURL);
         AuthnRequest authnRequest = this.samlLoginService.buildAuthnRequest(issuerValue, "https://login.microsoftonline.com/" + tenantId + "/saml2", assertionConsumerServiceURL);
         String redirectUrl = this.samlLoginService.redirectToAzure(request, response, authnRequest,tenantId);
         this.logger.info(redirectUrl);
         return redirectUrl;
      } catch (Exception var6) {
         this.logger.error("Exception during SAML login initiation: ", var6);
         return "";
      }
   }
}
