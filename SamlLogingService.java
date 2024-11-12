package com.tcm.framework.sos;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class SamlLogingService extends HttpServlet {
/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
//   private SamlDecodingLoginService samlDecodingLoginService = new SamlDecodingLoginService();
   private static final Logger logger = LoggerFactory.getLogger(SamlLogingService.class);
   private ServletContext servletContext;
   private DOMMetadataResolver metadataResolver;

   static {
		 try {
		 InitializationService.initialize();
		 } catch (Exception e) {
		 throw new RuntimeException("Error initializing OpenSAML", e);
//			 logger.error("Error intializing: ", e);
		 }
		 }

		
		public void initializeOpenSAML() {
			try {
				InitializationService.initialize();
			} catch (Exception e) {
				throw new RuntimeException("Error initializing OpenSAML", e);
			}
		}

		public AuthnRequest buildAuthnRequest(String issuerValue, String destination, String assertionConsumerServiceURL) {
		      try {
		         InitializationService.initialize();
		      } catch (InitializationException var9) {
		         logger.error("failed intializing open saml :" + var9);
		      }

		      Instant issueInstant = Instant.now();
		      DateTime issueDateTime = new DateTime(issueInstant.toEpochMilli(), DateTimeZone.UTC);
		      XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		      AuthnRequest authnRequest = (AuthnRequest)builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		      Issuer issuer = (Issuer)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		      issuer.setValue(issuerValue);
		      authnRequest.setIssuer(issuer);
		      authnRequest.setDestination(destination);
		      authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
		      authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		      authnRequest.setID("_" + UUID.randomUUID().toString());
		      authnRequest.setIssueInstant(issueDateTime);
		      return authnRequest;
		   }

		
		public String sendSamlRequest(AuthnRequest authnRequest) {
			try {
				Marshaller marshaller = XMLObjectProviderRegistrySupport
						.getMarshallerFactory().getMarshaller(authnRequest);
				Element authnRequestElement = marshaller.marshall(authnRequest);

				// Convert XML element to string
				TransformerFactory transformerFactory = TransformerFactory
						.newInstance();
				javax.xml.transform.Transformer transformer = transformerFactory
						.newTransformer();
				StringWriter writer = new StringWriter();
				transformer.transform(new DOMSource(authnRequestElement),
						new StreamResult(writer));
				return writer.toString();
			} catch (Exception e) {
				logger.error("Error sending SAML request: ", e);
				return null;
			}
		}

		
		public Response receiveSamlResponse(String samlResponse) {
			try {
				DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
						.newInstance();
				documentBuilderFactory.setNamespaceAware(true);
				Document document = documentBuilderFactory.newDocumentBuilder()
						.parse(new ByteArrayInputStream(samlResponse
								.getBytes(StandardCharsets.UTF_8)));

				Element element = document.getDocumentElement();
				UnmarshallerFactory unmarshallerFactory = org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
						.getUnmarshallerFactory();
				Unmarshaller unmarshaller = unmarshallerFactory
						.getUnmarshaller(element);
				return (Response) unmarshaller.unmarshall(element);
			} catch (Exception e) {
				logger.error("Error receiving SAML response: ", e);
				return null;
			}
		}

		
		public void signAuthnRequest(AuthnRequest authnRequest, PrivateKey privateKey, X509Certificate certificate) throws Exception {
		      BasicX509Credential credential = new BasicX509Credential(certificate, privateKey);
		      Signature signature = (Signature)XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
		      signature.setSigningCredential(credential);
		      signature.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		      signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
		      authnRequest.setSignature(signature);
		      Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);
		      if (marshaller == null) {
		         throw new SAMLException("Unable to locate marshaller for AuthnRequest object");
		      } else {
		         marshaller.marshall(authnRequest);
		         Signer.signObject(signature);
		      }
		   }
		
		
//		public void initializeMetadataResolver() {
//		    try {
//		        InitializationService.initialize();
//		    } catch (Exception e) {
//		        throw new RuntimeException("Error initializing OpenSAML", e);
//		    }
	//
//		    try {
//		        // Initialize parser
//		        BasicParserPool parser = new BasicParserPool();
//		        parser.initialize();
	//
//		        // Manually configure SAML metadata
//		        String metadataXML = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
//		                "<EntityDescriptor ID=\"_4340665c-b748-4db8-9fd0-c0467be76b82\" entityID=\"https://sts.windows.net/b4f1578a-47f9-4430-ada2-bb11543569b2/\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">" +
//		                "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
//		                "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />" +
//		                "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />" +
//		                "<Reference URI=\"#_4340665c-b748-4db8-9fd0-c0467be76b82\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />" +
//		                "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms>" +
//		                "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>IWAneWCdn3S9zmPY7kk0CTVb9pkHXt6gw2ELmbx9v9g=</DigestValue></Reference></SignedInfo>" +
//		                "<SignatureValue>rrK7eAyEr5Qs3/0rjXPOWoWM9nRP9flSFTN5scVA+BDsEM8xiOdiBpQS0XdP4OeCsUPMf+YDEQVbGC4QCNNeSxZT62qoWA0kOnBMX1dmMznYePfqF4cW1dQtxEKyzaL0KnE0jRDNAiQFm8LmhQG/mFgMM1a0hX2SS5fbwz8gS3LtYpwXdkTlTUdomIriKLx9dsXHuwQ1DFkEY/gUT4wW8PlfRWjff2hQASYfqgwDN+saovNSNAdZQU4D56nD6+tA2CAOXI7e1n3pHkpLFAjFUi0bqs60WadgElXdXmtStI8f6HJse1B9y7IJEgZHlV3zBbkH0NffuKqmkT0My9AZnA==</SignatureValue>" +
//		                "<KeyInfo><ds:X509Data xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Certificate>MIIC8DCCAdigAwIBAgIQNZf5zkTVfKFHnNuXehqRxTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNDA1MjgwODI4NTBaFw0yNzA1MjgwODI4NTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA11J34oiJootSlHEBAKuTIswjzT3IDPHcJ6zebiEkNK4WU1dclyIGmumPp/9VTsB+a6U7eCscfhXkpkYOqEL6rIjytHmLcZN0qgAdBLDUtj/BYCoq8bp5HlMdqIwGeVrasuK1PzUcEyYdShubsscd2n4FENhrImc+NoWd2chhQEnWvvIUb448izYim+wBCcl+3mOjqrVXcpFb96oppQxj+3mvM2jESiurUZ4gJsxZ9NpUaoQez2BNi8bdNrO4ZQv0D4tD7Slmz/WfPBl4Zjfhv6RXMZVb/9lfggnYplmeKwX1X37hJdG8o9rdObKwzv+kcSpxI8jKgVBm73wIDAQABozEwLzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUMt/kPO9tXzGNFdzwA6ng9e0c0NswHwYDVR0jBBgwFoAUMt/kPO9tXzGNFdzwA6ng9e0c0NswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdBVk5QFgLpmy7iNtu2HbV5JNt4pQGFGw8Zet0t/3g3H0XV6/ZC9bmyJawv5sB4GqF1DdgIZZ69/t42y02Jz9SACQKYYfki1H6o3RCATaOrNmZ0TwMgC88UPKdik/Mp+/ntc7PIBiQUnlLO17wz0kKnV6BBMPD+I1ddO5tRrW4C4bA9HTDFQpXdbdr+b3T6K7eAmDXx77OD8jz1NvK+xyy0ZCjvGvWx3I9sx2m8eUUOC4MJ6D7cb6NXc2tAl8FpTbV/dksotTJne6WUN4/TAd7I67gADGtxSGrVddN6e2+bUgkdcnLWznB8rOSyRfNx9fN+dDbB0DlaX2eg==</ds:X509Certificate></ds:X509Data></KeyInfo></Signature>" +
//		                "<Organization xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:dc="http://purl.org/dc/terms/" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><OrganizationName xml:lang=\"en-US\">Microsoft Corporation</OrganizationName><OrganizationDisplayName xml:lang=\"en-US\">Microsoft Corporation</OrganizationDisplayName><Address xml:lang=\"en-US\">One Microsoft Way</Address><City xml:lang=\"en-US\">Redmond</City><StateProvince xml:lang=\"en-US\">WA</StateProvince><PostalCode xml:lang=\"en-US\">98052</PostalCode><Country xml:lang=\"en-US\">US</Country></Organization>" +
//		                "<ContactPerson contactType=\"administrative\">" +
//		                "<GivenName>Administrator</GivenName><EmailAddress>admin@microsoft.com</EmailAddress>" +
//		                "</ContactPerson>" +
//		                "<ContactPerson contactType=\"technical\">" +
//		                "<GivenName>Technical Contact</GivenName><EmailAddress>tech@microsoft.com</EmailAddress>" +
//		                "</ContactPerson>" +
//		                "</EntityDescriptor>";
	//
//		        ByteArrayInputStream metadataStream = new ByteArrayInputStream(metadataXML.getBytes());
	//
//		        // Create metadata provider
//		        DOMMetadataResolver metadataResolver = new DOMMetadataResolver();
//		        metadataResolver.setId("metadataResolver");
//		        metadataResolver.setParserPool(parser);
//		        metadataResolver.initialize();
	//
//		        // Populate metadata provider
//		        EntityDescriptor entityDescriptor = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
//		                Configuration.getParserPool(), metadataStream);
//		        metadataResolver.getMetadataProviders().add(entityDescriptor);
	//
//		        this.metadataResolver = metadataResolver;
//		    } catch (Exception e) {
//		        logger.error("Error initializing metadata resolver: ", e);
//		        throw new RuntimeException("Error initializing metadata resolver", e);
//		    }
//		}
//		public void initializeMetadataResolver() {
//		    String metadataURL = "https://login.microsoftonline.com/b4f1578a-47f9-4430-ada2-bb11543569b2/federationmetadata/2007-06/federationmetadata.xml?appid=cb07938b-4857-4600-b38d-ad52e17b86b7";
	//
//		    try {
//		        InitializationService.initialize();
//		    } catch (Exception e) {
//		        throw new RuntimeException("Error initializing OpenSAML", e);
//		    }
	//
//		    try {
//		        // Initialize parser
//		        BasicParserPool parser = new BasicParserPool();
//		        parser.initialize();
	//
//		        // Create HTTP client
//		        CloseableHttpClient httpClient = HttpClients.createDefault();
	//
//		        // Create HTTPMetadataResolver
//		        HTTPMetadataResolver httpMetadataResolver = new HTTPMetadataResolver(
//		            httpClient, metadataURL);
//		        httpMetadataResolver.setRequireValidMetadata(true);
//		        httpMetadataResolver.setId("metadataResolver");
//		        httpMetadataResolver.initialize();
	//
//		        this.metadataResolver = httpMetadataResolver;
//		    } catch (Exception e) {
//		        logger.error("Error initializing metadata resolver: ", e);
//		        throw new RuntimeException("Error initializing metadata resolver",
//		            e);
//		    }
//		}
		 public void initializeMetadataResolver() throws SAXException, ComponentInitializationException, FileNotFoundException, org.xml.sax.SAXException {
		        String metadataFilePath = servletContext.getRealPath("/") + File.separator + 
		                                  "Route Compliance Management System - PRD" + File.separator + 
		                                  "xml" + File.separator + "6/7/2024" + File.separator;

		        if (!Files.exists(Paths.get(metadataFilePath), LinkOption.NOFOLLOW_LINKS)) {
		            throw new FileNotFoundException("Metadata file does not exist at the specified path: " + metadataFilePath);
		        }

		        try (FileInputStream metadataInputStream = new FileInputStream(new File(metadataFilePath))) {
		            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		            Element metadataElement = documentBuilder.parse(metadataInputStream).getDocumentElement();
		            
		            BasicParserPool parser = new BasicParserPool();
		            parser.initialize();
		            
		            DOMMetadataResolver metadataResolver = new DOMMetadataResolver(metadataElement);
		            metadataResolver.setId("metadataResolver");
		            metadataResolver.initialize();
		            
		            this.metadataResolver = metadataResolver;
		        } catch (FileNotFoundException e) {
		            logger.error("Metadata file not found: " + e);
		            throw new RuntimeException("Metadata file not found", e);
		        } catch (IOException | ParserConfigurationException e) {
		            logger.error("Error parsing metadata file: " + e);
		            throw new RuntimeException("Error parsing metadata file", e);
		        }
		    }

		    public MetadataResolver getMetadataResolver() {
		        return this.metadataResolver;
		    }
		    
		    
		    public List<X509Certificate> parseMetadata(String metadata) {
		        List<X509Certificate> trustedCertificates = new ArrayList<>(); // Initialize the list

		        try {
		            // Parse metadata document
		            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		            Document document = documentBuilder.parse(new ByteArrayInputStream(metadata.getBytes()));

		            // Navigate through the document and extract certificate elements
		            NodeList certificateNodes = document.getElementsByTagName("X509Certificate");
		            for (int i = 0; i < certificateNodes.getLength(); i++) {
		                Node certificateNode = certificateNodes.item(i);
		                String certificateData = certificateNode.getTextContent();
		                logger.info("Certificate Data :"+certificateData);

		                // Convert certificate data to X509Certificate
		                X509Certificate certificate = parseCertificate(certificateData);
		                if (certificate != null) {
		                    trustedCertificates.add(certificate);
		                }
		            }
		        } catch (Exception e) {
		            e.printStackTrace();
		        }

		        return trustedCertificates;
		    }

		   
		    public X509Certificate parseCertificate(String certificateData) {
//		    	will do it with codec otherwise it will give error  import org.apache.commons.codec.binary.Base64;

//		    	public X509Certificate parseCertificate(String certificateData) {
//		    	    try {
//		    	        // URL decode the certificate data
//		    	        String urlDecoded = URLDecoder.decode(certificateData, StandardCharsets.UTF_8.name());
//		    	        logger.info("Url decoded certificate data: " + urlDecoded);
//
//		    	        // Base64 decode the URL decoded string
//		    	        byte[] base64DecodedBytes = Base64.getDecoder().decode(urlDecoded);
//		    	        String base64Decoded = new String(base64DecodedBytes, StandardCharsets.UTF_8);
//		    	        logger.info("Base64 decoded certificate data: " + base64Decoded);
//
//		    	        // Generate the X509Certificate
//		    	        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//		    	        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(base64DecodedBytes)) {
//		    	            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
//		    	        } catch (IOException e) {
//		    	            logger.error("Error occurred during certificate parsing", e);
//		    	        }
//		    	    } catch (UnsupportedEncodingException e) {
//		    	        logger.error("Error occurred during URL decoding", e);
//		    	    } catch (CertificateException e) {
//		    	        logger.error("Error parsing certificate", e);
//		    	    }
//		    	    return null;
//		    	}

		    	
		    	
//		        try {
//		            // URL decode the certificate data
//		            String urlDecoded = URLDecoder.decode(certificateData, StandardCharsets.UTF_8.name());
//		            logger.info("Url decoded certificate data:"+urlDecoded);
//
//		            // Base64 decode the URL decoded string
//		           String base64Decoded = new String(Base64.getDecoder().decode(urlDecoded));
//		            logger.info("Base64 decoded certificate data:"+base64Decoded);
//
//
//		            // Generate the X509Certificate
//		            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//		            byte[] decodedBytes = base64Decoded.getBytes(StandardCharsets.UTF_8);
//		            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(decodedBytes)) {
//		                return (X509Certificate) certificateFactory.generateCertificate(inputStream);
//		            } catch (IOException e) {
//		                logger.error("Error occurred during certificate parsing", e);
//		            }
//		        } catch (UnsupportedEncodingException e) {
//		            logger.error("Error occurred during URL decoding", e);
//		        } catch (CertificateException e) {
//		            logger.error("Error parsing certificate", e);
//		        }
		        return null;
		    }



		    public String redirectToAzure(HttpServletRequest request, HttpServletResponse response, AuthnRequest authnRequest,String tenantId) throws IOException {
		        try {
		            String azureLoginUrl = "https://login.microsoftonline.com/" + tenantId + "/saml2";
		            String encodedAuthnRequest = encodeAndSignSAMLRequest(authnRequest);
		            logger.info("64bit: " + encodedAuthnRequest);
		            return azureLoginUrl + "?SAMLRequest=" + encodedAuthnRequest;
		        } catch (Exception e) {
		            logger.error("Error redirecting to Azure: ", e);
		            return "";
		        }
		    }

		    public static String encodeSAMLRequest(AuthnRequest authnRequest) {
		        try {
		            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		            Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);
		            Element authnRequestElement = marshaller.marshall(authnRequest);
		            String samlRequestXml = convertDocumentToString(authnRequestElement.getOwnerDocument());
		            logger.info("SAML Request XML: " + samlRequestXml);

		            byte[] inputBytes = samlRequestXml.getBytes(StandardCharsets.UTF_8);
		            Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
		            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		            try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(outputStream, deflater)) {
		                deflaterOutputStream.write(inputBytes);
		            }

		            byte[] deflatedBytes = outputStream.toByteArray();
		            String base64EncodedRequest = Base64.getEncoder().encodeToString(deflatedBytes);
		            logger.info("Base64 Encoded SAML Request: " + base64EncodedRequest);

		            if (!isValidBase64(base64EncodedRequest)) {
		                throw new IllegalArgumentException("Invalid Base64 encoded string");
		            }

		            return URLEncoder.encode(base64EncodedRequest, StandardCharsets.UTF_8.toString());
		        } catch (Exception e) {
		            logger.error("Error encoding SAML request: ", e);
		            return null;
		        }
		    }

		    private static boolean isValidBase64(String base64EncodedRequest) {
		        try {
		            byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedRequest);
		            String reEncodedString = Base64.getEncoder().encodeToString(decodedBytes);
		            return base64EncodedRequest.equals(reEncodedString);
		        } catch (IllegalArgumentException e) {
		            return false;
		        }
		    }

		    public static String convertDocumentToString(Document document) throws TransformerException {
		        StringWriter sw = new StringWriter();
		        TransformerFactory tf = TransformerFactory.newInstance();
		        Transformer transformer = tf.newTransformer();
		        transformer.setOutputProperty("omit-xml-declaration", "yes");
		        transformer.setOutputProperty("indent", "no");
		        transformer.transform(new DOMSource(document), new StreamResult(sw));
		        return sw.toString().replaceAll("\\n", "");
		    }

		    public String encodeAndSignSAMLRequest(AuthnRequest authnRequest) {
		        try {
		            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		            Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);
		            Element authnRequestElement = marshaller.marshall(authnRequest);
		            String samlRequestXml = convertDocumentToString(authnRequestElement.getOwnerDocument());
		            logger.info("SAML Request XML: " + samlRequestXml);

		            byte[] inputBytes = samlRequestXml.getBytes(StandardCharsets.UTF_8);
		            Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
		            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		            try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(outputStream, deflater)) {
		                deflaterOutputStream.write(inputBytes);
		            }

		            byte[] deflatedBytes = outputStream.toByteArray();
		            String base64EncodedRequest = Base64.getEncoder().encodeToString(deflatedBytes);
		            logger.info("Base64 Encoded SAML Request: " + base64EncodedRequest);
		            return URLEncoder.encode(base64EncodedRequest, StandardCharsets.UTF_8.toString());
		        } catch (Exception e) {
		            logger.error("Error encoding and signing SAML request: ", e);
		            return null;
		        }
		    }

		    public List<Assertion> extractAssertions(Response response) {
		        return response.getAssertions();
		     }

	   
	    }