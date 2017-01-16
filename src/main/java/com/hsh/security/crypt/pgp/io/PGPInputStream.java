package com.hsh.security.crypt.pgp.io;

import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.Stack;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import com.hsh.security.crypt.pgp.rfc4880.types.CompressionAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.HashAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.MessageFormatType;
import com.hsh.security.crypt.pgp.rfc4880.types.PublicKeyAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.SignatureType;
import com.hsh.security.crypt.pgp.tools.PGPUtils;

public class PGPInputStream extends InputStream {
	public class UncipheringReport {
		private String						originalFileName;
		private CompressionAlgorithmType	compressionAlgorithm			= CompressionAlgorithmType.ZIP;
		private MessageFormatType			fileFormat						= MessageFormatType.TEXT;
		private String						signedBy						= null;
		private boolean					onePassSignedMessage			= false;
		private boolean					signedMessage					= false;
		private boolean					signatureCheckSuccess			= false;
		private boolean					dataIntegrityProtected			= false;
		private boolean					messagePassDataIntegrityCheck	= false;
		private boolean					asciiArmored					= false;
		private SignatureType				signatureType					= SignatureType.CANONICAL_TEXT_DOCUMENT;
		private int						signatureVersion;
		private Date						signatureCreationTime;
		private HashAlgorithmType			signatureHashAlgorithm			= HashAlgorithmType.SHA1;
		private PublicKeyAlgorithmType		signaturePulicKeyAlgorithm		= PublicKeyAlgorithmType.RSA_SIGN;
		private boolean					clearSigned						= false;

		/**
		 * @return Renvoie clearSigned.
		 */
		public boolean isClearSigned() {
			return this.clearSigned;
		}
		/**
		 * @return Renvoie signaturePulicKeyAlgorithm.
		 */
		public PublicKeyAlgorithmType getSignaturePulicKeyAlgorithm() {
			return this.signaturePulicKeyAlgorithm;
		}
		/**
		 * @return Renvoie signatureType.
		 */
		public SignatureType getSignatureType() {
			return this.signatureType;
		}
		/**
		 * @return Renvoie signatureVersion.
		 */
		public int getSignatureVersion() {
			return this.signatureVersion;
		}
		/**
		 * @return Renvoie signatureCreationTime.
		 */
		public Date getSignatureCreationTime() {
			return this.signatureCreationTime;
		}
		/**
		 * @return Renvoie signatureHashAlgorithm.
		 */
		public HashAlgorithmType getSignatureHashAlgorithm() {
			return this.signatureHashAlgorithm;
		}
		/**
		 * @return Renvoie asciiArmored.
		 */
		public boolean isAsciiArmored() {
			return this.asciiArmored;
		}
		/**
		 * @return Renvoie compressionAlgorithm.
		 */
		public CompressionAlgorithmType getCompressionAlgorithm() {
			return this.compressionAlgorithm;
		}
		/**
		 * @return Renvoie fileFormat.
		 */
		public MessageFormatType getFileFormat() {
			return this.fileFormat;
		}
		/**
		 * @return Renvoie originalFileName.
		 */
		public String getOriginalFileName() {
			return this.originalFileName;
		}
		/**
		 * @return Renvoie onePassSignedMessage.
		 */
		public boolean isOnePassSignedMessage() {
			return this.onePassSignedMessage;
		}
		/**
		 * @return Renvoie signedMessage.
		 */
		public boolean isSignedMessage() {
			return this.signedMessage;
		}
		/**
		 * @return Renvoie signatureCheckSuccess.
		 */
		public boolean isSignatureCheckSuccess() {
			if (this.signedMessage) {
				return this.signatureCheckSuccess;
			} else {
				return false;
			}
		}
		/**
		 * @return Renvoie signedBy.
		 */
		public String getSignedBy() {
			return this.signedBy;
		}
		/**
		 * @return Renvoie dataIntegrityProtected.
		 */
		public boolean isDataIntegrityProtected() {
			return this.dataIntegrityProtected;
		}
		/**
		 * @return Renvoie messagePassDataIntegrityCheck.
		 */
		public boolean isMessagePassDataIntegrityCheck() {
			if (this.dataIntegrityProtected) {
				return this.messagePassDataIntegrityCheck;
			} else {
				return false;
			}
		}
		/* (non-Javadoc)
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "UncipheringReport [originalFileName=" + this.originalFileName + 
					",\n compressionAlgorithm=" + this.compressionAlgorithm + 
					",\n fileFormat=" + this.fileFormat +
					",\n signedBy=" + this.signedBy + 
					",\n onePassSignedMessage=" + this.onePassSignedMessage + 
					",\n signedMessage=" + this.signedMessage + 
					",\n signatureCheckSuccess=" + this.signatureCheckSuccess + 
					",\n dataIntegrityProtected=" + this.dataIntegrityProtected + 
					",\n messagePassDataIntegrityCheck=" + this.messagePassDataIntegrityCheck + 
					",\n asciiArmored=" + this.asciiArmored + 
					",\n clearSigned=" + this.clearSigned + 
					",\n signatureType=" + this.signatureType + 
					",\n signatureVersion=" + this.signatureVersion + 
					",\n signatureCreationTime=" + this.signatureCreationTime + 
					",\n signatureHashAlgorithm=" + this.signatureHashAlgorithm + 
					",\n signaturePulicKeyAlgorithm=" + this.signaturePulicKeyAlgorithm + 
					"]";
		}

	}

	private final InputStream inputStream;
	private final PGPSecretKeyRingCollection secretKeyRing;
	private final PGPPublicKeyRingCollection publicKeyRing;
	private final char[] passphrase;
	private final Stack<PGPObjectFactory> pgpPacketUnwrapperList = new Stack<PGPObjectFactory>();
	private final Stack<PGPOnePassSignature> onePassSignatureStack = new Stack<PGPOnePassSignature>();
	private PGPPrivateKey privateKey = null;
	private InputStream decryptedStream = null;
	private InputStream literalStream = null;
	private PGPPublicKeyEncryptedData encryptedData = null;
	private boolean pgpProcessFinalized = false;
	private boolean clearText = false;
	private PGPSignature clearSignature = null;
	private boolean noMoreReading = false;

	private final UncipheringReport report = new UncipheringReport();

	PGPInputStream(
			final InputStream pInputStream, final PGPPublicKeyRingCollection pPublicKeyRing, 
			final PGPSecretKeyRingCollection pSecretKeyRing,  final char[] pPasswd) throws IOException, PGPException, SignatureException {

		this.inputStream = PGPUtil.getDecoderStream(pInputStream);
		this.report.asciiArmored  = (this.inputStream instanceof ArmoredInputStream);
		if (this.report.isAsciiArmored()) {
			this.clearText = ((ArmoredInputStream)this.inputStream).isClearText();
			this.report.clearSigned = this.clearText;
		}

		this.publicKeyRing = pPublicKeyRing;
		this.secretKeyRing = pSecretKeyRing;
		this.passphrase = pPasswd;
		this.pgpPacketUnwrapperList.push(new BcPGPObjectFactory(this.inputStream));

		while (this.processPgp()) {
			;
		}
	}

	private boolean processPgp() throws IOException, PGPException {
		if (this.report.asciiArmored && ((ArmoredInputStream)this.inputStream).isClearText()) {
			this.literalStream = this.inputStream;
			return false;
		}
		while (!this.pgpPacketUnwrapperList.isEmpty()) {
			PGPObjectFactory lPgpFactory = this.pgpPacketUnwrapperList.peek();
			Object lPgpPacket = null;
			lPgpPacket = lPgpFactory.nextObject();
			if (lPgpPacket == null) {
				this.pgpPacketUnwrapperList.pop();
			} else {
				if (lPgpPacket instanceof PGPEncryptedDataList) {
					PGPEncryptedDataList lEncryptedDataList = (PGPEncryptedDataList) lPgpPacket;

					// find the private key
					this.populatePrivateKey(lEncryptedDataList);

					// prepare the stream for decryption
					this.decryptedStream = this.encryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(this.privateKey));

					// push decrypted stream to the top of the packet stack
					this.pgpPacketUnwrapperList.push(new BcPGPObjectFactory(this.decryptedStream));
				} else if (lPgpPacket instanceof PGPCompressedData) {
					PGPCompressedData lCompressedData = (PGPCompressedData) lPgpPacket;
					this.report.compressionAlgorithm  = CompressionAlgorithmType.getCompressionAlgorithm(lCompressedData.getAlgorithm());

					// push compressed data stream to the top of the packet stack
					this.pgpPacketUnwrapperList.push(new BcPGPObjectFactory(lCompressedData.getDataStream()));
				} else if (lPgpPacket instanceof PGPOnePassSignatureList) {
					// feed the one pass signature stack
					this.populateOnePassSignatureStack((PGPOnePassSignatureList) lPgpPacket);
				} else if (lPgpPacket instanceof PGPLiteralData) {
					PGPLiteralData lLiteralData = (PGPLiteralData) lPgpPacket;
					this.literalStream = lLiteralData.getInputStream();
					this.report.originalFileName = lLiteralData.getFileName();
					this.report.fileFormat = MessageFormatType.getMessageFormat(lLiteralData.getFormat());
					return false;
				} else if (lPgpPacket instanceof PGPSignatureList) {
					this.checkSignatures((PGPSignatureList)lPgpPacket);
				}
				return true;
			}
		}
		return false;
	}







	private void checkSignatures(final PGPSignatureList pSignatureList) throws PGPException {
		int lNbSignatures = pSignatureList.size();
		for (int i = 0; i < lNbSignatures; i++) {
			this.report.signedMessage = true;
			PGPSignature lSignature = pSignatureList.get(i);

			this.report.signatureType = SignatureType.getSignatureType(lSignature.getSignatureType());
			this.report.signatureVersion = lSignature.getVersion();
			this.report.signatureCreationTime = lSignature.getCreationTime();
			this.report.signatureHashAlgorithm = HashAlgorithmType.getHashAlgorithm(lSignature.getHashAlgorithm());
			this.report.signaturePulicKeyAlgorithm = PublicKeyAlgorithmType.getPublicKeyAlgorithm(lSignature.getKeyAlgorithm());
			System.out.println("checking signature: " + lSignature.getKeyID());
			PGPPublicKey lPublicKey = this.publicKeyRing.getPublicKey(lSignature.getKeyID());
			this.report.signedBy = lPublicKey.getUserIDs().hasNext()?(String)lPublicKey.getUserIDs().next():null;

			// if it's a "one pass" signature
			if (!this.onePassSignatureStack.isEmpty()) {
				PGPOnePassSignature lOnePassSignature = this.onePassSignatureStack.pop();
				System.out.println("checking signature: " + lOnePassSignature.getKeyID());
				if (lOnePassSignature.verify(lSignature)) {
					lPublicKey = this.publicKeyRing.getPublicKey(lOnePassSignature.getKeyID());
					Iterator<?> lUserIds = lPublicKey.getUserIDs();
					while (lUserIds.hasNext()) {
						String lUserId = (String) lUserIds.next();
						this.report.signedBy = lUserId;
						System.out.println("Signed by " + lUserId);
					}
					this.report.signatureCheckSuccess = true;
					System.out.println("Signature verified");
				} else {
					System.out.println("Signature verification failed");
				}
			} else {
				PGPContentVerifierBuilderProvider verifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();
				lSignature.init(verifierBuilderProvider, lPublicKey);
				this.clearSignature = lSignature;
			}
		}
	}

	private void populatePrivateKey(PGPEncryptedDataList pEncryptedDataList) throws PGPException, IllegalArgumentException {
		Iterator<?> lIterator = pEncryptedDataList.getEncryptedDataObjects();
		while ((this.privateKey == null) && lIterator.hasNext()) {
			PGPEncryptedData lEncryptedData = (PGPEncryptedData) lIterator.next();
			if (lEncryptedData instanceof PGPPublicKeyEncryptedData) {
				this.encryptedData = (PGPPublicKeyEncryptedData) lEncryptedData; // where the symetric key used to uncipher the msg is supposed to be
				this.report.dataIntegrityProtected = this.encryptedData.isIntegrityProtected();
				this.privateKey = PGPUtils.findPrivateKey(this.secretKeyRing, this.encryptedData.getKeyID(), this.passphrase); // in other words, try to find in the secretKeyRing, the "private key" that can unbox the "cyphering symetric key" from the "PGPPublicKeyEncryptedData"
			}
		}
		if (this.privateKey == null) {
			throw new IllegalArgumentException("no privateKey found in the secretKeyRing to unbox the symetric key needed to uncipher the message.");
		}
	}

	private void populateOnePassSignatureStack(final PGPOnePassSignatureList pOnePassSignatureList) throws PGPException {
		this.report.onePassSignedMessage = true;
		int lNbOnePassSignatures = pOnePassSignatureList.size();
		for (int i = 0; i < lNbOnePassSignatures; i++) {
			PGPOnePassSignature lOnePassSignature = pOnePassSignatureList.get(i);
			PGPPublicKey lPublicKey = this.publicKeyRing.getPublicKey(lOnePassSignature.getKeyID());
			lOnePassSignature.init(new BcPGPContentVerifierBuilderProvider(), lPublicKey);
			this.onePassSignatureStack.push(lOnePassSignature);
		}
	}

	private void finalizePgpProcess() throws IOException {
		try {
			while (this.processPgp()) {
				;
			}
			if ((this.encryptedData != null) && this.encryptedData.isIntegrityProtected()) {
				this.report.messagePassDataIntegrityCheck = this.encryptedData.verify();
				if (!this.report.messagePassDataIntegrityCheck) {
					System.out.println("Message failed integrity check");
				}
			}
			this.pgpProcessFinalized = true;
		} catch (PGPException lE) {
			lE.printStackTrace();
		}
	}






















	@Override
	public void close() throws IOException {
		this.literalStream.close();
		if (this.decryptedStream != null) {
			this.decryptedStream.close();
		}
		this.inputStream.close();
		super.close();
	}

	@Override
	public int read() throws IOException {
		int lChar = -1;

		// stop reading, there is nothing else to read.
		if (this.noMoreReading) {
			return lChar;
		}

		if (!this.report.isAsciiArmored() || !(this.literalStream instanceof ArmoredInputStream) ) {
			lChar = this.literalStream.read();
		} else if (!(((lChar = this.literalStream.read()) >= 0) && ((ArmoredInputStream)this.literalStream).isClearText())) {
			lChar = -1;
		}

		if (lChar == -1) {
			this.noMoreReading = true;
			this.finalizePgpProcess();
		} else {
			if (!this.onePassSignatureStack.isEmpty()) {
				for (int i = 0; i < this.onePassSignatureStack.size(); i++) {
					this.onePassSignatureStack.get(i).update((byte)lChar);
				}
			}
		}

		return lChar;
	}

	public boolean checkClearSignature(final InputStream pClearText) {
		this.report.signatureCheckSuccess = PGPUtils.checkClearSignature(this.clearSignature, pClearText);
		return this.report.signatureCheckSuccess;
	}

	/**
	 * @return Renvoie pgpProcessFinalized.
	 */
	public boolean isPgpProcessFinalized() {
		return this.pgpProcessFinalized;
	}

	/**
	 * @return Renvoie report.
	 */
	public UncipheringReport getReport() {
		return this.report;
	}
}
