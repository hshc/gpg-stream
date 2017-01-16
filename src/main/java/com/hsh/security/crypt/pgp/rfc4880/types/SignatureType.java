package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.openpgp.PGPSignature;

public enum SignatureType {

	BINARY_DOCUMENT("Binary document", PGPSignature.BINARY_DOCUMENT), 
	CANONICAL_TEXT_DOCUMENT("Canonical text document", PGPSignature.CANONICAL_TEXT_DOCUMENT), 
	STAND_ALONE("Standalone signature", PGPSignature.STAND_ALONE), 
	DEFAULT_CERTIFICATION("Generic certification of a User ID and Public-Key packet", PGPSignature.DEFAULT_CERTIFICATION), 
	NO_CERTIFICATION("Persona certification of a User ID and Public-Key packet", PGPSignature.NO_CERTIFICATION), 
	CASUAL_CERTIFICATION("Casual certification of a User ID and Public-Key packet", PGPSignature.CASUAL_CERTIFICATION), 
	POSITIVE_CERTIFICATION("Positive certification of a User ID and Public-Key packet", PGPSignature.POSITIVE_CERTIFICATION), 
	SUBKEY_BINDING("Subkey Binding Signature", PGPSignature.SUBKEY_BINDING), 
	PRIMARYKEY_BINDING("Primary Key Binding Signature", PGPSignature.PRIMARYKEY_BINDING), 
	DIRECT_KEY("Signature directly on a key", PGPSignature.DIRECT_KEY), 
	KEY_REVOCATION("Key revocation signature", PGPSignature.KEY_REVOCATION), 
	SUBKEY_REVOCATION("Subkey revocation signature", PGPSignature.SUBKEY_REVOCATION), 
	CERTIFICATION_REVOCATION("Certification revocation signature", PGPSignature.CERTIFICATION_REVOCATION), 
	TIMESTAMP("Timestamp signature", PGPSignature.TIMESTAMP), 
	THIRDPARTY_CONFIRMATION("Third-Party Confirmation signature", 0x50);

	private SignatureType(final String pLabel, final int pValue) {
		this.value = pValue;
		this.label = pLabel;
	}

	private final int		value;
	private final String	label;
	/**
	 * @return Renvoie value.
	 */
	public int getValue() {
		return this.value;
	}
	/**
	 * @return Renvoie label.
	 */
	public String getLabel() {
		return this.label;
	}
	@Override
	public String toString() {
		return Integer.toHexString(this.value)+" - "+this.label;
	}
	public static SignatureType getSignatureType(final int pValue) {
		for(final SignatureType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}
}
