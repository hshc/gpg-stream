package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

public enum SymmetricKeyAlgorithmType {

	NULL 		  ("Plaintext or unencrypted data"                                  , SymmetricKeyAlgorithmTags.NULL 		 ),
	IDEA 		  ("IDEA"                                                           , SymmetricKeyAlgorithmTags.IDEA 		 ),
	TRIPLE_DES    ("Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)", SymmetricKeyAlgorithmTags.TRIPLE_DES   ),
	CAST5 		  ("CAST5 (128 bit key, as per RFC 2144)"                           , SymmetricKeyAlgorithmTags.CAST5 		 ),
	BLOWFISH 	  ("Blowfish (128 bit key, 16 rounds)"                              , SymmetricKeyAlgorithmTags.BLOWFISH 	 ),
	SAFER 		  ("SAFER-SK128 (13 rounds)"                                        , SymmetricKeyAlgorithmTags.SAFER 		 ),
	DES 		  ("DES/SK"                                                         , SymmetricKeyAlgorithmTags.DES 		 ),
	AES_128 	  ("AES with 128-bit key"                                           , SymmetricKeyAlgorithmTags.AES_128 	 ),
	AES_192 	  ("AES with 192-bit key"                                           , SymmetricKeyAlgorithmTags.AES_192 	 ),
	AES_256 	  ("AES with 256-bit key"                                           , SymmetricKeyAlgorithmTags.AES_256 	 ),
	TWOFISH 	  ("Twofish"                                                        , SymmetricKeyAlgorithmTags.TWOFISH 	 ),
	CAMELLIA_128  ("Camellia with 128-bit key"                                      , SymmetricKeyAlgorithmTags.CAMELLIA_128 ),
	CAMELLIA_192  ("Camellia with 192-bit key"                                      , SymmetricKeyAlgorithmTags.CAMELLIA_192 ),
	CAMELLIA_256  ("Camellia with 256-bit key"                                      , SymmetricKeyAlgorithmTags.CAMELLIA_256 );

	private SymmetricKeyAlgorithmType(final String pLabel, final int pValue) {
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
	public static SymmetricKeyAlgorithmType getSymmetricKeyAlgorithm(final int pValue) {
		for(final SymmetricKeyAlgorithmType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}
}
