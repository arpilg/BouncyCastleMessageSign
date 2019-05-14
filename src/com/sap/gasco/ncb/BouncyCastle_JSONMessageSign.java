package com.sap.gasco.ncb;

import org.json.JSONObject;
import org.json.XML;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sap.aii.mapping.api.AbstractTrace;
import com.sap.aii.mapping.api.AbstractTransformation;
import com.sap.aii.mapping.api.DynamicConfiguration;
import com.sap.aii.mapping.api.DynamicConfigurationKey;
import com.sap.aii.mapping.api.StreamTransformationException;
import com.sap.aii.mapping.api.TransformationInput;
import com.sap.aii.mapping.api.TransformationOutput;
import com.sap.engine.interfaces.messaging.api.MessageDirection;
import com.sap.engine.interfaces.messaging.api.MessageKey;
import com.sap.engine.interfaces.messaging.api.PublicAPIAccessFactory;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;

/*** DEVELOPER : ARPIL GUPTA(ATOS) ***/
public class BouncyCastle_JSONMessageSign extends AbstractTransformation { //https://stackoverflow.com/questions/10703416/sign-data-using-pkcs-7-in-java?answertab=active#tab-top
	 public static String PATH_TO_KEYSTORE  = "E:/Gasco/Sadad/Java mapping/BouncyCastle_JsonSigning/NCB_jks.jks";
	 public static String KEY_ALIAS_IN_KEYSTORE = "ncb_jks";
	 public static String KEYSTORE_PASSWORD  = "123456"; 
	 public static String msgID = null;
	 public static String NodeNameForJsonConversion = null;
	
	public static void main(String[] args) throws StreamTransformationException, FileNotFoundException,
	TransformerConfigurationException, TransformerFactoryConfigurationError{ 		
		BouncyCastle_JSONMessageSign obj = new BouncyCastle_JSONMessageSign();
		FileInputStream fin = new FileInputStream("E:/Gasco/Sadad/Java mapping/BouncyCastle_JsonSigning/Input.xml");
		FileOutputStream fout = new FileOutputStream("E:/Gasco/Sadad/Java mapping/BouncyCastle_JsonSigning/Output.txt");

		try {
			obj.execute(fin, fout);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void transform(TransformationInput in, TransformationOutput out) throws StreamTransformationException {
		BouncyCastle_JSONMessageSign.PATH_TO_KEYSTORE = in.getInputParameters().getString("PATH_TO_KEYSTORE");	
		BouncyCastle_JSONMessageSign.KEY_ALIAS_IN_KEYSTORE  = in.getInputParameters().getString("KEY_ALIAS_IN_KEYSTORE");
		BouncyCastle_JSONMessageSign.KEYSTORE_PASSWORD = in.getInputParameters().getString("KEYSTORE_PASSWORD");
		BouncyCastle_JSONMessageSign.msgID = in.getInputHeader().getMessageId();

		AbstractTrace trace = (AbstractTrace) getTrace(); //Capture trace object and write trace for debugging purpose.
		DynamicConfiguration DynConfig = in.getDynamicConfiguration(); //get the DynamicConfiguration Running Instance
		if( DynConfig == null){
			throw new StreamTransformationException("Unable to load the Dynamic Configuration Object!");
		}		
		//Define the Key that we want to read
		DynamicConfigurationKey key = DynamicConfigurationKey.create("nodeNamespace", "nodeName");	
		BouncyCastle_JSONMessageSign.NodeNameForJsonConversion = DynConfig.get(key);
		writeJSON_AuditLog("Node name for Message: ",BouncyCastle_JSONMessageSign.NodeNameForJsonConversion);
		
		try {
			this.execute(in.getInputPayload().getInputStream(), out.getOutputPayload().getOutputStream());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw new StreamTransformationException("Exception in Transform Javamap step");
		}
	}

	public void execute(InputStream in, OutputStream out) throws StreamTransformationException, Exception {		
		String JSONString= null;
		BouncyCastle_JSONMessageSign signer = new BouncyCastle_JSONMessageSign();
		Document doc = null ;
		DocumentBuilder builder;
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		StringWriter sw = new StringWriter();
		  
		try {
			builder = factory.newDocumentBuilder();
			doc = builder.parse(in);
			Node node = doc.getElementsByTagName(BouncyCastle_JSONMessageSign.NodeNameForJsonConversion).item(0);
			
		    Transformer t = TransformerFactory.newInstance().newTransformer();
		    t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		    t.transform(new DOMSource(node), new StreamResult(sw));
		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
//		System.out.println(sw.toString());		

		String s = sw.toString();
		//Convert xml to String, Considering everything as string
		JSONString = XML.toJSONObject(s,true).toString();
		writeJSON_AuditLog("Converted JSON String1: ", JSONString);
			JSONString = JSONString.replace("{\"SARIETransferRq\":", "");
			JSONString = JSONString.replace("{\"IntraTransferRq\":", "");
			JSONString = replaceLast(JSONString,"}","");

		writeJSON_AuditLog("Converted JSON String2: ", JSONString);
		
		NodeList nodes = doc.getElementsByTagName("Signature");
		KeyStore keyStore = signer.loadKeyStore();

		CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);
		//Sign Json String
		String signedBase64Data = signer.signPkcs7(JSONString.getBytes(), signatureGenerator);
//		System.out.println(signedBase64Data);

		Element docElement = doc.getDocumentElement();
        Node node = doc.createElement("Signature");
        docElement.appendChild(node);
        
		Element signValElement = doc.createElement("SignatureValue");
		signValElement.appendChild(doc.createTextNode(signedBase64Data)); 		
		doc.getElementsByTagName("Signature").item(0).appendChild(signValElement);

		try {
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.transform(new DOMSource(doc), new StreamResult(out));
		} catch (TransformerConfigurationException e) {
			// Implement exception handling
		} catch (TransformerException e) {
			// Implement exception handling
		}
	}

	private void writeJSON_AuditLog(String Description, String Data) throws StreamTransformationException {
		// TODO Auto-generated method stub
		final String DASH = "-";
		String uuidTimeLow = msgID.substring(0, 8);
		String uuidTimeMid = msgID.substring(8, 12);
		String uuidTimeHighAndVersion = msgID.substring(12, 16);
		String uuidClockSeqAndReserved = msgID.substring(16, 18);
		String uuidClockSeqLow = msgID.substring(18, 20);
		String uuidNode = msgID.substring(20, 32);
		String msgUUID = uuidTimeLow + DASH + uuidTimeMid + DASH + uuidTimeHighAndVersion + DASH + uuidClockSeqAndReserved + uuidClockSeqLow + DASH + uuidNode;
		// Construct message key (com.sap.engine.interfaces.messaging.api.MessageKey)
		// for retrieved message ID and outbound message direction (com.sap.engine.interfaces.messaging.api.MessageDirection).
		MessageKey msgKey = new MessageKey(msgUUID, MessageDirection.OUTBOUND);
		// Add new audit log entry with status ‘Success’ (com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus)

		AuditAccess msgAuditAccessor = null;
		try {
			msgAuditAccessor = PublicAPIAccessFactory.getPublicAPIAccess().getAuditAccess();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw new StreamTransformationException("***Unable to write Audit Log***");
		}		
		msgAuditAccessor.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS,Description+Data);
	}

	KeyStore loadKeyStore() throws Exception {
		KeyStore keystore = KeyStore.getInstance("JKS");
		InputStream is = new FileInputStream(PATH_TO_KEYSTORE);
		keystore.load(is, BouncyCastle_JSONMessageSign.KEYSTORE_PASSWORD.toCharArray());
		return keystore;
	}

	CMSSignedDataGenerator setUpProvider(final KeyStore keyStore) throws Exception {
		Security.addProvider((Provider)new BouncyCastleProvider());
		final Certificate[] arrcertificate = keyStore.getCertificateChain(BouncyCastle_JSONMessageSign.KEY_ALIAS_IN_KEYSTORE);
		List arrayList = new ArrayList(arrcertificate.length);

		for(int i=0;i<arrcertificate.length;i++)
		{
			arrayList.add(arrcertificate[i]);
		}

		final JcaCertStore jcaCertStore = new JcaCertStore((Collection)arrayList);
		final Certificate certificate = keyStore.getCertificate(BouncyCastle_JSONMessageSign.KEY_ALIAS_IN_KEYSTORE);

		final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("1234".toCharArray());
		final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(BouncyCastle_JSONMessageSign.KEY_ALIAS_IN_KEYSTORE, passwordProtection);
		final PrivateKey privateKey = privateKeyEntry.getPrivateKey();

		final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);

		final CMSSignedDataGenerator cMSSignedDataGenerator = new CMSSignedDataGenerator();
		cMSSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, (X509Certificate)certificate));
		cMSSignedDataGenerator.addCertificates((Store)jcaCertStore);
		return cMSSignedDataGenerator;
	}

	String signPkcs7(final byte[] arrby, final CMSSignedDataGenerator cMSSignedDataGenerator) throws Exception {
		final CMSProcessableByteArray cMSProcessableByteArray = new CMSProcessableByteArray(arrby);
		final CMSSignedData cMSSignedData = cMSSignedDataGenerator.generate((CMSTypedData)cMSProcessableByteArray);
		//        System.out.println("Plain Data##########:\n" + new String(arrby));
		final String signedBase64Data = new String(Base64.encode((byte[])cMSSignedData.getEncoded()));
		return signedBase64Data;
	}	
	
	public static String replaceLast(String string, String toReplace, String replacement) {
	    int pos = string.lastIndexOf(toReplace);
	    if (pos > -1) {
	        return string.substring(0, pos)
	             + replacement
	             + string.substring(pos + toReplace.length(), string.length());
	    } else {
	        return string;
	    }
	}
}