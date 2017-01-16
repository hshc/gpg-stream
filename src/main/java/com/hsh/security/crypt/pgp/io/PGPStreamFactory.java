package com.hsh.security.crypt.pgp.io;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

import com.hsh.security.crypt.pgp.rfc4880.types.CompressionAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.HashAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.SymmetricKeyAlgorithmType;
import com.hsh.security.crypt.pgp.tools.PGPUtils;

public class PGPStreamFactory {
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private final static int			BUFFER_SIZE			= 1 << 16; // should always be power of 2

	private boolean					armored = true;
	private boolean					encrypted = true;
	private boolean					compressed = true;
	private boolean					signed = true;
	private boolean					integrityCheck = true;
	private final char[]				passphrase;
	private CompressionAlgorithmType	compressionAlgorithm	= CompressionAlgorithmType.ZLIB;
	private char						literalDataFormat		= PGPLiteralData.TEXT;
	private SymmetricKeyAlgorithmType	symetricKeyAlgorithm	= SymmetricKeyAlgorithmType.AES_256;
	private HashAlgorithmType			signatureHashAlgorithm	= HashAlgorithmType.SHA1;

	private final PGPPublicKeyRingCollection publicKeyRing;
	private final PGPSecretKeyRingCollection secretKeyRing;
	private final PGPSignatureGenerator signatureCreator;


	private PGPStreamFactory(final PGPPublicKeyRingCollection pPublicKeyRing, 
			final PGPSecretKeyRingCollection pSecretKeyRing, 
			final char[] pPassphrase) throws PGPException {
		this.publicKeyRing = pPublicKeyRing;
		this.secretKeyRing = pSecretKeyRing;
		this.passphrase = pPassphrase;

		PGPSecretKey lSecretKey = null;

		if (this.secretKeyRing != null) {
			lSecretKey = PGPUtils.findSigningKey(this.secretKeyRing);
		}
		if ((lSecretKey != null) && (pPassphrase != null)) {
			// Initialize signature generator
			this.signatureCreator = PGPUtils.buildSignatureGenerator(lSecretKey, pPassphrase, this.signatureHashAlgorithm);
		} else {
			this.signed = false;
			this.signatureCreator = null;
		}
	}

	/**
	 * This method returns a factory that can provide input and output stream suitable for a secured relation between the owner of the factory (providing the secret key and the password) and the provider of the public key.
	 * 
	 * @param pPublicKey key used to cipher the message when sending (output stream) or check the signature when receiving (input stream)
	 * @param pSecretKey key used to sign the message when sending (output stream) or uncipher the message when receiving (input stream)
	 * @param pPassphrase passphrase used to unwrap the private key nested in the pSecretKey
	 * 
	 * @return PGPStreamFactory
	 * @throws PGPException 
	 */
	public static PGPStreamFactory getInstance(
			final PGPPublicKeyRingCollection pPublicKeyRing, 
			final PGPSecretKeyRingCollection pSecretKeyRing, 
			final char[] pPassphrase) throws PGPException {
		return new PGPStreamFactory(pPublicKeyRing, pSecretKeyRing, pPassphrase);
	}

	public PGPOutputStream getPGPOutputStream(final OutputStream pOutputStream, final String pOriginalFileName) throws Exception {
		if (this.encrypted && (this.publicKeyRing == null)) {
			throw new IllegalArgumentException("You try to encrypt data but your public key ring is 'null'");
		}
		return new PGPOutputStream(
				pOutputStream, 
				BUFFER_SIZE, 
				this.armored, 
				this.encrypted, 
				this.compressed, 
				this.signatureCreator, 
				this.integrityCheck, 
				this.compressionAlgorithm, 
				this.literalDataFormat, 
				this.symetricKeyAlgorithm, 
				pOriginalFileName, 
//				this.encrypted?PGPUtils.findPublicKeyForEncryption(this.publicKeyRing):null, 
				this.encrypted?PGPUtils.findPublicKeysForEncryption(this.publicKeyRing):null, 
				this.secretKeyRing==null?null:PGPUtils.findSigningKey(this.secretKeyRing)
				);
	}

	public PGPInputStream getPGPInputStream(final InputStream pInputStream) throws Exception {
		return new PGPInputStream(pInputStream, 
				this.publicKeyRing, 
				this.secretKeyRing, 
				this.passphrase);
	}

	/**
	 * @return Renvoie armored.
	 */
	public boolean isArmoringEnabled() {
		return this.armored;
	}

	public void enableArmoring() {
		this.armored = true;
	}
	public void disableArmoring() {
		this.armored = false;
	}

	/**
	 * @return Renvoie encrypted.
	 */
	public boolean isEncryptionEnabled() {
		return this.encrypted;
	}
	public void enableEncyption() {
		this.encrypted = true;
	}
	public void disableEncyption() {
		this.encrypted = false;
	}

	/**
	 * @return Renvoie compressed.
	 */
	public boolean isCompressionEnabled() {
		return this.compressed;
	}
	public void enableCompression() {
		this.compressed = true;
	}
	public void disableCompression() {
		this.compressed = false;
	}

	/**
	 * @return Renvoie signed.
	 */
	public boolean isSigningEnable() {
		return this.signed;
	}
	public void enableSigning() {
		this.signed = true;
	}
	public void disableSigning() {
		this.signed = false;
	}

	/**
	 * @return Renvoie integrityCheck.
	 */
	public boolean isIntegrityCheckingEnable() {
		return this.integrityCheck;
	}
	public void enableIntegrityChecking() {
		this.integrityCheck = true;
	}
	public void disableIntegrityChecking() {
		this.integrityCheck = false;
	}

	/**
	 * @return Renvoie compressionAlgorithm.
	 */
	public CompressionAlgorithmType getCompressionAlgorithm() {
		return this.compressionAlgorithm;
	}
	/**
	 * @param pCompressionAlgorithm
	 *            compressionAlgorithm à définir.
	 */
	public void setCompressionAlgorithm(CompressionAlgorithmType pCompressionAlgorithm) {
		this.compressionAlgorithm = pCompressionAlgorithm;
	}

	/**
	 * @return Renvoie literalDataFormat.
	 */
	public char getLiteralDataFormat() {
		return this.literalDataFormat;
	}
	/**
	 * @param pLiteralDataFormat
	 *            literalDataFormat à définir.
	 */
	public void setLiteralDataFormat(char pLiteralDataFormat) {
		this.literalDataFormat = pLiteralDataFormat;
	}

	/**
	 * @return Renvoie symetricKeyAlgorithm.
	 */
	public SymmetricKeyAlgorithmType getSymetricKeyAlgorithm() {
		return this.symetricKeyAlgorithm;
	}

	/**
	 * @param pSymetricKelAlgorithm
	 *            symetricKeyAlgorithm à définir.
	 */
	public void setSymetricKeyAlgorithm(SymmetricKeyAlgorithmType pSymetricKelAlgorithm) {
		this.symetricKeyAlgorithm = pSymetricKelAlgorithm;
	}
	/**
	 * @return Renvoie signatureHashAlgorithm.
	 */
	public HashAlgorithmType getSignatureHashAlgorithm() {
		return this.signatureHashAlgorithm;
	}
	/**
	 * @param pSignatureHashAlgorithm
	 *            signatureHashAlgorithm à définir.
	 */
	public void setSignatureHashAlgorithm(HashAlgorithmType pSignatureHashAlgorithm) {
		this.signatureHashAlgorithm = pSignatureHashAlgorithm;
	}

}
