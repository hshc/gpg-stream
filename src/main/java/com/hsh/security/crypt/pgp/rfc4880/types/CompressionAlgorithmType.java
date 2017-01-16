package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

public enum CompressionAlgorithmType {

	UNCOMPRESSED("UNCOMPRESSED" , CompressionAlgorithmTags.UNCOMPRESSED),
	ZIP("ZIP"                   , CompressionAlgorithmTags.ZIP),
	ZLIB("ZLIB"                 , CompressionAlgorithmTags.ZLIB),
	BZIP2("BZIP2"               , CompressionAlgorithmTags.BZIP2);

	private CompressionAlgorithmType(final String pLabel, final int pValue) {
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

	public static CompressionAlgorithmType getCompressionAlgorithm(final int pValue) {
		for(final CompressionAlgorithmType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}
}
