package com.tcm.framework.sos;



import com.tcm.framework.service.Resources;
import com.tcm.framework.webcontroller.BaseController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.tcm.framework.service.Resources;
import com.tcm.nestle.bo.AdminProfile;
import com.tcm.nestle.dao.UserProfileDao;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;

@WebServlet(name = "AssertionConsumerService", urlPatterns =
{ "/saml/acs" })
public class AssertionConsumerService extends BaseController
{
	private final SamlLogingService samlLoginService = new SamlLogingService();
	private final EncryptionUtil encryptionUtil = new EncryptionUtil();
	String roleKey = null;
	String email = null;
	String notOnOrAfter = null;
	HashMap<String, String> rmProductionAndQaRoles = null;
	AdminProfile user = new AdminProfile();
	String encryptedCurrentTime = null;
	String encryptedEmail = null;
	String encryptedNotOnOrAfter = null;
	String encryptedParam1 = null;
	String encryptedParam2 = null;
	String encryptedParam3 = null;
	String encryptedParam4 = null;
	String encryptedkeyRole = null;
	 List<String> groups = new ArrayList<>();
	 List<String> roles = new ArrayList<>();
	 String group = null;
		String role = null;

	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
			IOException
	{
		this.handleSamlResponse(req, resp);
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException
	{
		this.handleSamlResponse(req, resp);
	}

	public void handleSamlResponse(HttpServletRequest request, HttpServletResponse response)
	{
		try
		{
			// logger.info("Handling SAML response...");
			String samlResponse = request.getParameter("SAMLResponse");
			if (samlResponse == null)
			{
				logger.error("SAMLResponse parameter not found in request body");
			}

			// logger.info("Raw SAMLResponse parameter: " + samlResponse);
			byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
			String decodedSamlResponse = new String(decodedBytes, StandardCharsets.UTF_8);
			logger.info("Decoded SAMLResponse: " + decodedSamlResponse);
			Response samlResponseObject = this.samlLoginService
					.receiveSamlResponse(decodedSamlResponse);
			logger.debug("SAML Response object received: " + samlResponseObject);
			List<Assertion> assertions = samlLoginService.extractAssertions(samlResponseObject);
			// logger.info("Extracted " + assertions.size() +
			// " assertions from SAML response.");

			// Read metadata file
			// String metadataFilePath = getServletContext().getRealPath("/") +
			// File.separator + "metadata" + File.separator
			// + "xml" ;
			// String metadataContent = new
			// String(Files.readAllBytes(Paths.get(metadataFilePath)));
			// logger.debug("Metadata content: " + metadataContent);
			//
			// // Check metadata
			// if (metadataContent.trim().isEmpty()) {
			// logger.error("Metadata file is empty or not properly read.");
			// response.sendRedirect("/error?error=empty_metadata");
			// return;
			// }
			//
			// List<X509Certificate> trustedCertificates =
			// samlLoginService.parseMetadata(metadataContent);
			// // logger.info("Trusted certificates loaded from metadata.");

			// Validate signature
			// boolean isValid =
			// samlLoginService.validateSignature(samlResponseObject,
			// trustedCertificates);
			// // logger.info("SAML response signature validation result: " +
			// isValid);

			// Process assertions

			for (Assertion assertion : assertions)
			{
				// Extract desired attributes
				for (AttributeStatement attributeStatement : assertion.getAttributeStatements())
				{
					for (Attribute attribute : attributeStatement.getAttributes())
					{
						String attributeName = attribute.getName();
						List<XMLObject> attributeValues = attribute.getAttributeValues();
						for (XMLObject attributeValue : attributeValues)
						{
							String attributeValueString = attributeValue.getDOM().getTextContent();
							 logger.info("Attribute: " + attributeName +
							 ", Value: " + attributeValueString);
							// Check if the attribute is the email address
							if ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
									.equals(attributeName))
							{
								email = attributeValueString;
								logger.info("Email extracted: " + email);
							}
							 if ("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups".equals(attributeName)) {
				                    groups.add(attributeValueString);
				                    logger.debug("Group added: " + attributeValueString);
				                }
							 if ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/Role".equals(attributeName)) {
				                    roles.add(attributeValueString);
				                    logger.debug("Role added: " + attributeValueString);
				                }

						}
					}
				}

				// Check SubjectConfirmationData
				for (SubjectConfirmation subjectConfirmation : assertion.getSubject()
						.getSubjectConfirmations())
				{
					SubjectConfirmationData subjectConfirmationData = subjectConfirmation
							.getSubjectConfirmationData();
					if (subjectConfirmationData.getNotOnOrAfter() != null)
					{
						notOnOrAfter = subjectConfirmationData.getNotOnOrAfter().toString();
						// logger.info("NotOnOrAfter from SubjectConfirmationData: "
						// + notOnOrAfter);
					}
				}

				Conditions conditions = assertion.getConditions();
				if (conditions != null && conditions.getNotOnOrAfter() != null)
				{
					notOnOrAfter = conditions.getNotOnOrAfter().toString();
					// logger.info("NotOnOrAfter from Conditions: " +
					// notOnOrAfter);
				}
			}
			logger.info("combining roles and group");
			String group = String.join(", ", groups);
			logger.info("groups"+groups);
			String role = String.join(", ", roles);
			logger.info("roles"+role);


			if (email != null && notOnOrAfter != null && role != null && group !=null  )
				
			{ 

				if (!"PMICLD SG Audit_Mobile_A_BASIS_ALL_ODDM IGA PRD".equals(group)){
					logger.info("Roles: " + roles);
					logger.info("Email: " + email);
					
					
				if (roles.contains("PMICLDSGAuditAdminPortalABASISALLODDMIGAPRD"))
				{
					logger.info("inside admin functionality");
					user = UserProfileDao.findUser(email);
					if (user != null)
					{
						logger.info("user found");
					}
			else
					{
						logger.info("user not found, creating user");
						int result = UserProfileDao.addingSsoAdmins(email);
						if (result > 0)
						{
							logger.info("User created successfully.");
						}
						else
						{
							logger.error("Failed to create user.");
						}
					}
				}}
//				else
//				{
//					encryptedkeyRole=encryptionUtil.encrypt(roleKey);
//					encryptedParam4=encryptionUtil.encrypt("role");
//				}

				encryptedCurrentTime = encryptionUtil.encrypt(Instant.now().toString());
				encryptedEmail = encryptionUtil.encrypt(email);
				encryptedNotOnOrAfter = encryptionUtil.encrypt(notOnOrAfter);
				encryptedParam1 = encryptionUtil.encrypt("email");
				encryptedParam2 = encryptionUtil.encrypt("notOnOrAfter");
				encryptedParam3 = encryptionUtil.encrypt("currentTime");

				logger.info("Sending Parsed Saml Response To Angular");
				String callbackurl="https://pmida.rtdtradetracker.com/dist/#/login";	

//				 String callbackurl="https://pmida.rtdtradetracker.com/dist/#/login";				
				 response.sendRedirect(callbackurl
						+ "?"
						+ URLEncoder.encode(encryptedParam1, StandardCharsets.UTF_8.toString())
						+ "="
						+ URLEncoder.encode(encryptedEmail, StandardCharsets.UTF_8.toString())
						+ "&"
						+ URLEncoder.encode(encryptedParam2, StandardCharsets.UTF_8.toString())
						+ "="
						+ URLEncoder.encode(encryptedNotOnOrAfter,
								StandardCharsets.UTF_8.toString())
						+ "&"
						+ URLEncoder.encode(encryptedParam3, StandardCharsets.UTF_8.toString())
						+ "="
						+ URLEncoder.encode(encryptedCurrentTime, StandardCharsets.UTF_8.toString()));
			}
			else
			{
				logger.warn("No NotOnOrAfter found.");
				logger.warn("No email found.");
				response.sendRedirect("/error?error=unknown");

			}

		}
		catch (Exception e)
		{
			logger.error("Error handling SAML response: ", e);
			try
			{
				response.sendRedirect("/error?error=unknown");
			}
			catch (IOException e1)
			{
				logger.error("Error redirecting to error page: ", e1);
			}
		}

	}
}