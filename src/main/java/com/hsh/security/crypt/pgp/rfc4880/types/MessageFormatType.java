package com.hsh.security.crypt.pgp.rfc4880.types;

import org.bouncycastle.openpgp.PGPLiteralData;

public enum MessageFormatType {

	BINARY("BINARY", PGPLiteralData.BINARY),
	TEXT  ("TEXT"  , PGPLiteralData.TEXT  ),
	UTF8  ("UTF8"  , PGPLiteralData.UTF8  );

	private MessageFormatType(final String pLabel, final int pValue) {
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
		return Integer.toString(this.value)+" - "+this.label;
	}
	public static MessageFormatType getMessageFormat(final int pValue) {
		for(final MessageFormatType obj : values()) {
			if (obj.value == pValue) {
				return obj;
			}
		}
		throw new IllegalArgumentException("Unsupported code '"+pValue+"'");
	}
}
