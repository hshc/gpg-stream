package com.hsh.security.crypt.pgp.io;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

import com.hsh.security.crypt.pgp.rfc4880.types.CompressionAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.SymmetricKeyAlgorithmType;
import com.hsh.security.crypt.pgp.tools.PGPUtils;

public class PGPOutputStream extends OutputStream {
	private final static int			BUFFER_SIZE			= 1 << 16; // should always be power of 2

	private final OutputStream outputStream;
	private final OutputStream outDecoratedStream;

	private ArmoredOutputStream outArmoredStream = null;
	private PGPEncryptedDataGenerator dataEncryptor = null	;
	private PGPCompressedDataGenerator compressedDataGenerator = null;
	private PGPSignatureGenerator signatureCreator = null;
	private PGPLiteralDataGenerator literalDataGenerator = null;

	private final boolean						integrityCheck;
	private final String						originalFileName;
	private final CompressionAlgorithmType		compressionAlgorithm;
	private final char						literalDataFormat;
	private final SymmetricKeyAlgorithmType	symetricKeylAlgorithm;

	PGPOutputStream(
			final OutputStream pOutputStream, 
			final int pBufferSize, 
			final boolean pArmored, 
			final boolean pEncrypted, 
			final boolean pCompressed, 
			final PGPSignatureGenerator pSignatureCreator, 
			final boolean pIntegrityCheck, 
			final CompressionAlgorithmType pCompressionAlgorithm, 
			final char pLiteralDataFormat,
			final SymmetricKeyAlgorithmType pSymetricKeyAlgorithm, 
			final String pOriginalFileName, 
			//			final PGPPublicKey pPublicKey, 
			final PGPPublicKey[] pPublicKeys, 
			final PGPSecretKey pSecretKey) throws Exception {
		super();
		this.outputStream = pOutputStream;
		this.integrityCheck = pIntegrityCheck;
		this.compressionAlgorithm = pCompressionAlgorithm;
		this.literalDataFormat = pLiteralDataFormat;
		this.symetricKeylAlgorithm = pSymetricKeyAlgorithm;
		this.originalFileName = pOriginalFileName;

		this.outDecoratedStream = this.startCiphering(
				pOutputStream, 
				pArmored, 
				pEncrypted, 
				pCompressed, 
				pSignatureCreator, 
				pOriginalFileName, 
				//				pPublicKey, 
				pPublicKeys, 
				pSecretKey);
	}

	private OutputStream startCiphering(
			final OutputStream pOutputStream, 
			final boolean pArmored, 
			final boolean pEncrypted, 
			final boolean pCompressed, 
			final PGPSignatureGenerator pSignatureCreator, 
			final String pOriginalFileName,
			//			final PGPPublicKey pPublicKey, 
			final PGPPublicKey[] pPublicKeys, 
			final PGPSecretKey pSecretKey) throws Exception {
		OutputStream lOutDecoratedStream = pOutputStream;
		if (pArmored) {
			// Decorate with armored stream -> in/armored/out
			lOutDecoratedStream = this.outArmoredStream = new ArmoredOutputStream(lOutDecoratedStream);
		} else {
			this.outArmoredStream = null;
		}

		if (pEncrypted) {
			// Initialize data encryptor
			//			this.dataEncryptor = PGPUtils.buildDataEncryptor(pPublicKey, this.integrityCheck, this.symetricKeylAlgorithm);
			this.dataEncryptor = PGPUtils.buildDataEncryptor(pPublicKeys, this.integrityCheck, this.symetricKeylAlgorithm);
			// Decorate with encrypted stream -> in/encrypted/(armored|clear)/out
			lOutDecoratedStream = this.dataEncryptor.open(lOutDecoratedStream, new byte[BUFFER_SIZE]);
		} else {
			this.dataEncryptor = null;
		}

		if (pCompressed) {
			// Initialize compressed data generator
			this.compressedDataGenerator = new PGPCompressedDataGenerator(this.compressionAlgorithm.getValue());
			// Decorate with compressed stream -> in/compressed/encrypted/(armored|clear)/out
			lOutDecoratedStream = this.compressedDataGenerator.open(lOutDecoratedStream);
		} else {
			this.compressedDataGenerator = null;
		}

		if (pSignatureCreator != null) {
			// Generate 5.4. One-Pass Signature Packets (Tag 4)
			PGPUtils.writeOnePassSignaturePacket(pSecretKey, lOutDecoratedStream, pSignatureCreator);
			this.signatureCreator = pSignatureCreator;
		}

		// Initialize literal data generator
		this.literalDataGenerator = new PGPLiteralDataGenerator();
		// Decorate with literal stream -> in/literal/compressed/encrypted/(armored|clear)/out
		lOutDecoratedStream = this.literalDataGenerator.open(lOutDecoratedStream, this.literalDataFormat, pOriginalFileName!=null?pOriginalFileName:"_CONSOLE", new Date(), new byte[BUFFER_SIZE]);
		return lOutDecoratedStream;
	}

	@Override
	public void write(final int pByte) throws IOException {
		if (this.outDecoratedStream != null) {
			this.outDecoratedStream.write(pByte);
			if (this.isSigned()) {
				this.signatureCreator.update((byte) pByte);
			}
		}
	}

	@Override
	public void write(final byte[] pByte) throws IOException {
		this.write(pByte, 0, pByte.length);
	}

	@Override
	public void write(final byte[] pByte, final int pOffset, final int pLength) throws IOException {
		if (this.outDecoratedStream != null) {
			this.outDecoratedStream.write(pByte, pOffset, pLength);
			if (this.isSigned()) {
				this.signatureCreator.update(pByte, pOffset, pLength);
			}
		}
	}

	@Override
	public void close() throws IOException {
		this.literalDataGenerator.close();

		if (this.isSigned()) {
			// Generate the signature, compress, encrypt and write to the "out" stream
			try {
				this.signatureCreator.generate().encode(this.outDecoratedStream);
			} catch (PGPException e) {
				throw new IOException(e.getMessage());
			}
		}

		if (this.isCompressed()) {
			this.compressedDataGenerator.close();
		}
		if (this.isEncrypted()) {
			this.dataEncryptor.close();
		}
		if (this.isArmored()) {
			this.outArmoredStream.close();
		}
		this.outputStream.flush();
	}

	/**
	 * @return Renvoie bufferSize.
	 */
	public static int getBufferSize() {
		return BUFFER_SIZE;
	}

	/**
	 * @return Renvoie armored.
	 */
	public boolean isArmored() {
		return this.outArmoredStream != null;
	}

	/**
	 * @return Renvoie encrypted.
	 */
	public boolean isEncrypted() {
		return this.dataEncryptor != null;
	}

	/**
	 * @return Renvoie compressed.
	 */
	public boolean isCompressed() {
		return this.compressedDataGenerator != null;
	}

	/**
	 * @return Renvoie signed.
	 */
	public boolean isSigned() {
		return this.signatureCreator != null;
	}

	/**
	 * @return Renvoie integrityCheck.
	 */
	public boolean isIntegrityCheck() {
		return this.integrityCheck;
	}

	/**
	 * @return Renvoie compressionAlgorithm.
	 */
	public CompressionAlgorithmType getCompressionAlgorithm() {
		return this.compressionAlgorithm;
	}

	/**
	 * @return Renvoie literalDataFormat.
	 */
	public char getLiteralDataFormat() {
		return this.literalDataFormat;
	}

	/**
	 * @return Renvoie symetricKeylAlgorithm.
	 */
	public SymmetricKeyAlgorithmType getSymetricKeylAlgorithm() {
		return this.symetricKeylAlgorithm;
	}

	/**
	 * @return Renvoie originalFileName.
	 */
	public String getOriginalFileName() {
		return this.originalFileName;
	}
}
