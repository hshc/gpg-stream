package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.bcpg.HashAlgorithmTags;

public enum HashAlgorithmType {

	MD5        ("MD5"                    , HashAlgorithmTags.MD5        ),
	SHA1       ("SHA-1"                  , HashAlgorithmTags.SHA1       ),
	RIPEMD160  ("RIPE-MD/160"            , HashAlgorithmTags.RIPEMD160  ),
	DOUBLE_SHA ("double-width SHA"       , HashAlgorithmTags.DOUBLE_SHA ),
	MD2        ("MD2"                    , HashAlgorithmTags.MD2        ),
	TIGER_192  ("TIGER/192"              , HashAlgorithmTags.TIGER_192  ),
	HAVAL_5_160("HAVAL (5 pass, 160-bit)", HashAlgorithmTags.HAVAL_5_160),
	SHA256     ("SHA-256"                , HashAlgorithmTags.SHA256     ),
	SHA384     ("SHA-384"                , HashAlgorithmTags.SHA384     ),
	SHA512     ("SHA-512"                , HashAlgorithmTags.SHA512     ),
	SHA224     ("SHA-224"                , HashAlgorithmTags.SHA224     );

	private HashAlgorithmType(final String pLabel, final int pValue) {
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
	public static HashAlgorithmType getHashAlgorithm(final int pValue) {
		for(final HashAlgorithmType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}

}
