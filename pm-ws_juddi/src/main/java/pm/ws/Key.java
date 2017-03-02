
package pm;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for docUserPair complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="docUserPair">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="documentId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="userId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "key", propOrder = { "key", "algorithm" })

public class Key {

	@XmlElement(required = true)
	protected String key;
	@XmlElement(required = true)
	protected String algorithm;

	public Key(java.security.Key k) throws NoSuchAlgorithmException {
		setKey(k);
	}

	/**
	 * Gets the value of the key property.
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public java.security.Key getKey() {
		// decode the base64 encoded string
		byte[] decodedKey = Base64.getDecoder().decode(key);
		// rebuild key using SecretKeySpec
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
	}

	/**
	 * Sets the value of the key property.
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * @throws NoSuchAlgorithmException
	 * 
	 */
	public void setKey(java.security.Key key) throws NoSuchAlgorithmException {
		this.algorithm = key.getAlgorithm();
		// get base64 encoded version of the key
		this.key = Base64.getEncoder().encodeToString(key.getEncoded());
	}
}
