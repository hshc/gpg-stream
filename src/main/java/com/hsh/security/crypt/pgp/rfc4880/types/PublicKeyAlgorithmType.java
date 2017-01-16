package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyAlgorithmType {

	RSA_GENERAL 	("RSA (Encrypt or Sign)"                             , PublicKeyAlgorithmTags.RSA_GENERAL    ),
	RSA_ENCRYPT 	("RSA Encrypt-Only"                                  , PublicKeyAlgorithmTags.RSA_ENCRYPT    ),
	RSA_SIGN 		("RSA Sign-Only"                                     , PublicKeyAlgorithmTags.RSA_SIGN       ),
	ELGAMAL_ENCRYPT	("Elgamal (Encrypt-Only)"                            , PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),
	DSA 			("DSA (Digital Signature Standard)"                  , PublicKeyAlgorithmTags.DSA            ),
	EC 				("Elliptic Curve"                                    , PublicKeyAlgorithmTags.EC             ),
	ECDSA 			("ECDSA"                                             , PublicKeyAlgorithmTags.ECDSA          ),
	ELGAMAL_GENERAL	("Elgamal (Encrypt or Sign)"                         , PublicKeyAlgorithmTags.ELGAMAL_GENERAL),
	DIFFIE_HELLMAN 	("Diffie-Hellman (X9.42, as defined for IETF-S/MIME)", PublicKeyAlgorithmTags.DIFFIE_HELLMAN );

	private PublicKeyAlgorithmType(final String pLabel, final int pValue) {
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
		return this.value+" - "+this.label;
	}
	public static PublicKeyAlgorithmType getPublicKeyAlgorithm(final int pValue) {
		for(final PublicKeyAlgorithmType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}

}
