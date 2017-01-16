package com.hsh.security.crypt.pgp.tools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.hsh.security.crypt.pgp.rfc4880.types.HashAlgorithmType;
import com.hsh.security.crypt.pgp.rfc4880.types.SymmetricKeyAlgorithmType;

public class PGPUtils {
	private static final int[]	MASTER_KEY_CERTIFICATION_TYPES	= 
			new int[] {
		/* 0x13: Positive certification of a User ID and Public-Key packet.
		 * The issuer of this certification has done substantial
		 * verification of the claim of identity.
		 * 
		 * Most OpenPGP implementations make their "key signatures" as 0x10
		 * certifications.  Some implementations can issue 0x11-0x13
		 * certifications, but few differentiate between the types.
		 */
		PGPSignature.POSITIVE_CERTIFICATION, 
		/* 0x12: Casual certification of a User ID and Public-Key packet.
		 * The issuer of this certification has done some casual
		 * verification of the claim of identity.
		 */
		PGPSignature.CASUAL_CERTIFICATION, 
		/* 0x11: Persona certification of a User ID and Public-Key packet.
		 * The issuer of this certification has not done any verification of
		 * the claim that the owner of this key is the User ID specified.
		 */
		PGPSignature.NO_CERTIFICATION,
		/* 0x10: Generic certification of a User ID and Public-Key packet.
		 * The issuer of this certification does not make any particular
		 * assertion as to how well the certifier has checked that the owner
		 * of the key is in fact the person described by the User ID.
		 */
		PGPSignature.DEFAULT_CERTIFICATION
	};

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	//	/**
	//	 * Method to use if one wants to bypass the jce local policy restrictions
	//	 * 
	//	 * @param pPublicKey
	//	 * @param pCheckIntegrity
	//	 * @param pSymetricKeylAlgorithm
	//	 * @return
	//	 */
	//	public static PGPEncryptedDataGenerator buildDataEncryptor(final PGPPublicKey pPublicKey, final boolean pCheckIntegrity, final SymmetricKeyAlgorithmType pSymetricKeylAlgorithm) {
	//		PGPEncryptedDataGenerator lDataEncryptor;
	//		PGPDataEncryptorBuilder lDataEncryptorBuilder = new BcPGPDataEncryptorBuilder(pSymetricKeylAlgorithm.getValue())
	//		.setWithIntegrityPacket(pCheckIntegrity)
	//		.setSecureRandom(new SecureRandom());
	//
	//		lDataEncryptor = new PGPEncryptedDataGenerator(lDataEncryptorBuilder);
	//		// add public key to encryptor
	//		lDataEncryptor.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pPublicKey));
	//		// add hash algorithm to encryptor
	//		lDataEncryptor.addMethod(new BcPBEKeyEncryptionMethodGenerator("Hash: SHA1".toCharArray()));
	//		return lDataEncryptor;
	//	}


	/**
	 * Method to use if one wants to bypass the jce local policy restrictions
	 * 
	 * @param pPgpPublicKeyRingCollection
	 * @param pCheckIntegrity
	 * @param pSymetricKeylAlgorithm
	 * @return
	 */
	public static PGPEncryptedDataGenerator buildDataEncryptor(final PGPPublicKey[] pPublicKeys, final boolean pCheckIntegrity, final SymmetricKeyAlgorithmType pSymetricKeylAlgorithm) {
		PGPEncryptedDataGenerator lDataEncryptor;
		PGPDataEncryptorBuilder lDataEncryptorBuilder = new BcPGPDataEncryptorBuilder(pSymetricKeylAlgorithm.getValue())
		.setWithIntegrityPacket(pCheckIntegrity)
		.setSecureRandom(new SecureRandom());

		lDataEncryptor = new PGPEncryptedDataGenerator(lDataEncryptorBuilder);
		// add public key to encryptor
		//		lDataEncryptor.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(lPublicKey));
		for (PGPPublicKey lPublicKey : pPublicKeys) {
			lDataEncryptor.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(lPublicKey));
		}
		// add hash algorithm to encryptor
		lDataEncryptor.addMethod(new BcPBEKeyEncryptionMethodGenerator("Hash: SHA1".toCharArray()));
		return lDataEncryptor;
	}


	/**
	 * This method can be used instead of buildDataEncryptor if one wants to be dependent of the jce local policy management.
	 * 
	 * @param pPublicKey
	 * @param pCheckIntegrity
	 * @param pSymetricKeylAlgorithm
	 * @return
	 */
	public static PGPEncryptedDataGenerator buildJceBasedDataEncryptor(final PGPPublicKey pPublicKey, final boolean pCheckIntegrity, final SymmetricKeyAlgorithmType pSymetricKeylAlgorithm) {
		PGPEncryptedDataGenerator lDataEncryptor;
		PGPDataEncryptorBuilder lDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(pSymetricKeylAlgorithm.getValue())
		.setWithIntegrityPacket(pCheckIntegrity)
		.setSecureRandom(new SecureRandom());

		lDataEncryptor = new PGPEncryptedDataGenerator(lDataEncryptorBuilder);
		lDataEncryptor.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pPublicKey));
		return lDataEncryptor;
	}

	/**
	 * Description:
	 * 
	 * @param pSecretKey
	 * @param pPassphrase
	 * @return
	 * @throws PGPException
	 */
	public static PGPSignatureGenerator buildSignatureGenerator(final PGPSecretKey pSecretKey, final char[] pPassphrase, final HashAlgorithmType pSignatureHashAlgorithm) throws PGPException {
		PGPPrivateKey lPrivateKey = extractPrivateKey(pSecretKey, pPassphrase);
		PGPContentSignerBuilder lSignerBuilder = new BcPGPContentSignerBuilder(pSecretKey.getPublicKey().getAlgorithm(), pSignatureHashAlgorithm.getValue());
		PGPSignatureGenerator lSignatureCreator = new PGPSignatureGenerator(lSignerBuilder);
		lSignatureCreator.init(PGPSignature.BINARY_DOCUMENT, lPrivateKey);
		return lSignatureCreator;
	}

	/**
	 * Description:
	 * 
	 * @param pSecretKey
	 * @param pOutCypheredStream
	 * @param pSignatureCreator
	 * @throws IOException
	 * @throws PGPException
	 */
	public static void writeOnePassSignaturePacket(final PGPSecretKey pSecretKey, OutputStream pOutCypheredStream, PGPSignatureGenerator pSignatureCreator) throws IOException, PGPException {
		Iterator<?> it = pSecretKey.getPublicKey().getUserIDs();
		if (it.hasNext()) {
			PGPSignatureSubpacketGenerator lSubSignatureCreator = new PGPSignatureSubpacketGenerator();
			lSubSignatureCreator.setSignerUserID(false, (String)it.next());
			pSignatureCreator.setHashedSubpackets(lSubSignatureCreator.generate());
		}
		// Generate 5.4. One-Pass Signature Packets (Tag 4)
		pSignatureCreator.generateOnePassVersion(false).encode(pOutCypheredStream);
	}

	/**
	 * Retrieve the receiver's suitable public key to encrypt the message
	 * 
	 * @param pPubKeyringCollection receiver public keyring collection (collection of one keyring)
	 * @return
	 */
	public static PGPPublicKey findPublicKeyForEncryption(final PGPPublicKeyRingCollection pPubKeyringCollection) {
		return findPublicKeys(pPubKeyringCollection, false)[0];
	}

	/**
	 * Retrieve the receivers suitable public keys to encrypt the message
	 * 
	 * @param pPubKeyringCollection receivers public keyrings collection
	 * @return
	 */
	public static PGPPublicKey[] findPublicKeysForEncryption(PGPPublicKeyRingCollection pPubKeyringCollection) {
		return findPublicKeys(pPubKeyringCollection, false);
	}


	/**
	 * Retrieve the sender's suitable public key to check the signature
	 * 
	 * @param pPubKeyringCollection sender public key ring
	 * @return
	 */
	public static PGPPublicKey findPublicKeyForSignChecking(final PGPPublicKeyRingCollection pPubKeyringCollection) {
		return findPublicKeys(pPubKeyringCollection, true)[0];
	}

	//	/**
	//	 * Description:
	//	 * 
	//	 * @param pIsForSignCheck
	//	 * @param pPubKeyringCollection
	//	 * @return
	//	 * @throws IllegalArgumentException
	//	 */
	//	private static PGPPublicKey findPublicKey(final PGPPublicKeyRingCollection pPubKeyringCollection, final boolean pIsForSignCheck) throws IllegalArgumentException {
	//		// Loop through the collection till we find a key suitable for encryption.
	//		PGPPublicKey lPublicKey = null;
	//		Iterator<?> lKeyringCollIter = pPubKeyringCollection.getKeyRings();
	//		while ((lPublicKey == null) && lKeyringCollIter.hasNext()) {
	//			PGPPublicKeyRing lKeyRing = (PGPPublicKeyRing)lKeyringCollIter.next();
	//			Iterator<?> lKeyRingIter = lKeyRing.getPublicKeys();
	//			while ((lPublicKey == null) && lKeyRingIter.hasNext()) {
	//				PGPPublicKey lPubKey = (PGPPublicKey)lKeyRingIter.next();
	//				if (lPubKey.isEncryptionKey() &&
	//						(// rfc4880 - tags 14 - By convention, the top-level key provides 
	//								// signature services, and the subkeys provide encryption services.
	//								pIsForSignCheck == lPubKey.isMasterKey())) { 
	//					lPublicKey = lPubKey;
	//				}
	//			}
	//		}
	//
	//		if (lPublicKey == null) {
	//			throw new IllegalArgumentException("Can't find public key in the key ring.");
	//		}
	//		if (!isForEncryption(lPublicKey)) {
	//			throw new IllegalArgumentException("KeyID " + lPublicKey.getKeyID() + " not flagged for encryption.");
	//		}
	//
	//		return lPublicKey;
	//	}

	/**
	 * Description:
	 * 
	 * @param pIsForSignCheck
	 * @param pPubKeyringCollection
	 * @return
	 * @throws IllegalArgumentException
	 */
	private static PGPPublicKey[] findPublicKeys(PGPPublicKeyRingCollection pPubKeyringCollection, boolean pIsForSignCheck) {
		Set<PGPPublicKey> lPgpPubKeys = new HashSet<PGPPublicKey>();
		// Loop through the collection till we find a key suitable for encryption.
		Iterator<?> lKeyringCollIter = pPubKeyringCollection.getKeyRings();
		while (lKeyringCollIter.hasNext()) {
			PGPPublicKeyRing lKeyRing = (PGPPublicKeyRing)lKeyringCollIter.next();
			Iterator<?> lKeyRingIter = lKeyRing.getPublicKeys();
			while (lKeyRingIter.hasNext()) {
				PGPPublicKey lPubKey = (PGPPublicKey)lKeyRingIter.next();
				if (lPubKey.isEncryptionKey() &&
						(// rfc4880 - tags 14 - By convention, the top-level key provides 
								// signature services, and the subkeys provide encryption services.
								pIsForSignCheck == lPubKey.isMasterKey())) { 
					if (!isForEncryption(lPubKey)) {
						throw new IllegalArgumentException("KeyID " + lPubKey.getKeyID() + " not flagged for encryption.");
					}
					lPgpPubKeys.add(lPubKey);
				}
			}
		}

		if (lPgpPubKeys.isEmpty()) {
			throw new IllegalArgumentException("Can't find public key in the key ring.");
		}

		return lPgpPubKeys.toArray(new PGPPublicKey[lPgpPubKeys.size()]);
	}


	//	/**
	//	 * Description:
	//	 * 
	//	 * @param pIsForSignCheck
	//	 * @param pPubKeyring
	//	 * @return
	//	 * @throws IllegalArgumentException
	//	 */
	//	private static PGPPublicKey findPublicKey(final PGPPublicKeyRing pPubKeyring, final boolean pIsForSignCheck) throws IllegalArgumentException {
	//		// Loop through the collection till we find a key suitable for encryption.
	//		PGPPublicKey lPublicKey = null;
	//		PGPPublicKeyRing lKeyRing = pPubKeyring;
	//		Iterator<?> lKeyRingIter = lKeyRing.getPublicKeys();
	//		while ((lPublicKey == null) && lKeyRingIter.hasNext()) {
	//			PGPPublicKey lPubKey = (PGPPublicKey)lKeyRingIter.next();
	//			if (lPubKey.isEncryptionKey() &&
	//					(// rfc4880 - tags 14 - By convention, the top-level key provides 
	//							// signature services, and the subkeys provide encryption services.
	//							pIsForSignCheck == lPubKey.isMasterKey())) { 
	//				lPublicKey = lPubKey;
	//			}
	//		}
	//
	//		if (lPublicKey == null) {
	//			throw new IllegalArgumentException("Can't find public key in the key ring.");
	//		}
	//		if (!isForEncryption(lPublicKey)) {
	//			throw new IllegalArgumentException("KeyID " + lPublicKey.getKeyID() + " not flagged for encryption.");
	//		}
	//
	//		return lPublicKey;
	//	}


	/**
	 * Load a secret key ring collection from a stream and find a secret key to sign
	 * 
	 * @param pInSecretKeyStream the stream used to load the secret key ring
	 * @return the secret key used for signature
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPSecretKey findSigningKey(final InputStream pInSecretKeyStream) throws IOException, PGPException {

		PGPSecretKeyRingCollection lSecKeyringCollection = null;
		lSecKeyringCollection = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pInSecretKeyStream));
		return findSigningKey(lSecKeyringCollection);
	}

	/**
	 * Find a secret key to sign from a secret key ring
	 * 
	 * @param pSecKeyringCollection
	 * @return the secret key used for signature
	 * @throws IllegalArgumentException
	 */
	public static PGPSecretKey findSigningKey(final PGPSecretKeyRingCollection pSecKeyringCollection) throws IllegalArgumentException {
		// Loop through the collection till we find a key suitable for signing.
		PGPSecretKey lSecretKey = null;
		Iterator<?> lKeyringCollIter = pSecKeyringCollection.getKeyRings();
		while ((lSecretKey == null) && lKeyringCollIter.hasNext()) {
			PGPSecretKeyRing lKeyRing = (PGPSecretKeyRing)lKeyringCollIter.next();
			Iterator<?> lKeyRingIter = lKeyRing.getSecretKeys();
			while ((lSecretKey == null) && lKeyRingIter.hasNext()) {
				PGPSecretKey lSecKey = (PGPSecretKey)lKeyRingIter.next();
				if (lSecKey.isSigningKey() && !lSecKey.isPrivateKeyEmpty()) {
					lSecretKey = lSecKey;
				}
			}
		}

		// Validate secret key
		if (lSecretKey == null) {
			throw new IllegalArgumentException("Can't find private key in the key ring.");
		}
		if (!lSecretKey.isSigningKey()) {
			throw new IllegalArgumentException("Private key does not allow signing.");
		}
		if (lSecretKey.getPublicKey().isRevoked()) {
			throw new IllegalArgumentException("Private key has been revoked.");
		}
		if (!hasKeyFlags(lSecretKey.getPublicKey(), KeyFlags.SIGN_DATA)) {
			throw new IllegalArgumentException("Key cannot be used for signing.");
		}

		return lSecretKey;
	}

	/**
	 * Description:
	 * 
	 * @param pPgpSec
	 * @param pKeyId
	 * @param pPass
	 * @return
	 * @throws PGPException
	 */
	public static PGPPrivateKey findSecretKeyForUnciphering(final PGPSecretKeyRingCollection pPgpSec, final long pKeyId, final char[] pPass) throws PGPException {

		PGPSecretKey lPgpSecKey = null;

		lPgpSecKey = pPgpSec.getSecretKey(pKeyId);

		if (lPgpSecKey == null) {
			return null;
		}

		PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pPass);
		return lPgpSecKey.extractPrivateKey(decryptor);
	}

	/**
	 * Load a secret key ring collection from <tt>pInSecretKeyStream</tt> and get the secret key corresponding to <tt>pKeyID</tt> if it exists.
	 * 
	 * @param pInSecretKeyStream
	 *            input stream representing a key ring collection.
	 * @param pKeyID
	 *            keyID we want.
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public static PGPSecretKey findSecretKey(final InputStream pInSecretKeyStream, final long pKeyID) throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection lSecKeyringColl = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pInSecretKeyStream));
		return lSecKeyringColl.getSecretKey(pKeyID);
	}

	/**
	 * Load a secret key ring collection from <tt>pInSecretKeyStream</tt> and get the private key corresponding to <tt>pKeyID</tt> if it exists.
	 * 
	 * @param pInSecretKeyStream
	 *            input stream representing a key ring collection.
	 * @param pKeyID
	 *            keyID we want.
	 * @param pPassword
	 *            passphrase to decrypt secret key with.
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public static PGPPrivateKey findPrivateKey(final InputStream pInSecretKeyStream, final long pKeyID, final char[] pPassword) throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection lSecKeyringColl = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pInSecretKeyStream));
		return findPrivateKey(lSecKeyringColl, pKeyID, pPassword);
	}

	/**
	 * Get the private key corresponding to <tt>pKeyID</tt> if it exists in the secret key ring collection.
	 * 
	 * @param pSecKeyringColl input key ring collection.
	 * @param pKeyID
	 *            keyID we want.
	 * @param pPassword
	 *            passphrase to decrypt secret key with.
	 * @return Returns the corresponding private key to the key ID provided in parameters or <tt>null</tt> if no key has been found.
	 * @throws PGPException
	 */
	public static PGPPrivateKey findPrivateKey(final PGPSecretKeyRingCollection pSecKeyringColl, final long pKeyID, final char[] pPassword) throws PGPException {
		PGPSecretKey lSecretKey = pSecKeyringColl.getSecretKey(pKeyID);
		return extractPrivateKey(lSecretKey, pPassword);
	}

	/**
	 * Load a secret key and find the private key in it
	 * 
	 * @param pInSecretKey
	 *            The secret key
	 * @param pPassword
	 *            passphrase to decrypt secret key with
	 * @return Returns the private key stored in the input secret key or <tt>null</tt> if the input secret key is <tt>null</tt>
	 * @throws PGPException
	 */
	public static PGPPrivateKey extractPrivateKey(PGPSecretKey pInSecretKey, char[] pPassword) throws PGPException {
		if (pInSecretKey == null) {
			return null;
		}

		BcPBESecretKeyDecryptorBuilder lSecKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
		PBESecretKeyDecryptor lSecKeyDecryptor = lSecKeyDecryptorBuilder.build(pPassword);
		return pInSecretKey.extractPrivateKey(lSecKeyDecryptor);
	}


	/**
	 * From LockBox Lobs PGP Encryption tools. http://www.lockboxlabs.org/content/downloads
	 * 
	 * I didn't think it was worth having to import a 4meg lib for three methods
	 * 
	 * @param pPublicKey
	 * @return
	 */
	public static boolean isForEncryption(final PGPPublicKey pPublicKey) {
		switch(pPublicKey.getAlgorithm()) {
		case PublicKeyAlgorithmTags.RSA_SIGN:
		case PublicKeyAlgorithmTags.DSA:
		case PublicKeyAlgorithmTags.EC:
		case PublicKeyAlgorithmTags.ECDSA:
			return false;
		}

		return hasKeyFlags(pPublicKey, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
	}

	/**
	 * If the public key <u>is the master key</u>: 
	 * <ul>
	 * <li>check that signature type (RFC 4880 §5.2.1) related to this master key is one of the types declared in the <tt>MASTER_KEY_CERTIFICATION_TYPES</tt> list</li>
	 * <li><u>and</u> that one of its key flags (see RFC 4880 §5.2.3.21) corresponds to the required key usage</li>
	 * </ul>
	 * 
	 * If the public key is a subkey:
	 * <ul>
	 * <li>check that the related signature type (RFC 4880 §5.2.1) is a <tt>SUBKEY_BINDING</tt> type (0x18)</li>
	 * <li><u>and</u> that one of its key flags (see RFC 4880 §5.2.3.21) corresponds to the required key usage</li>
	 * </ul>
	 * 
	 * @param pPublicKey the public key used to sign
	 * @param pKeyUsage "logical OR" of key flags used as a filter (mask) on the signature types of the public key to check if at least one those usages is declared for this key
	 * @return
	 */
	private static boolean hasKeyFlags(final PGPPublicKey pPublicKey, final int pKeyUsage) {
		Iterator<?> lSignatureIterator = null;
		PGPSignature lSignature = null;
		if (pPublicKey.isMasterKey()) {
			for (int i = 0; i != PGPUtils.MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
				lSignatureIterator = pPublicKey.getSignaturesOfType(PGPUtils.MASTER_KEY_CERTIFICATION_TYPES[i]);
				while(lSignatureIterator.hasNext()) {
					lSignature = (PGPSignature)lSignatureIterator.next();
					if (isMatchingUsage(lSignature, pKeyUsage)) {
						return true;
					}
				}
			}
		} else {
			lSignatureIterator = pPublicKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
			while (lSignatureIterator.hasNext()) {
				lSignature = (PGPSignature)lSignatureIterator.next();
				if (isMatchingUsage(lSignature, pKeyUsage)) {
					return true;
				}
			}
		}
		return false;
	}

	private static boolean isMatchingUsage(final PGPSignature pSignature, final int pKeyUsages) {
		if (pSignature.hasSubpackets()) {
			PGPSignatureSubpacketVector sv = pSignature.getHashedSubPackets();
			if (sv.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS)) {
				if ((sv.getKeyFlags() & pKeyUsages) != 0) {
					return true;
				} else {
					return false;
				}
			}
		}
		return true;	
	}


	public static boolean checkClearSignature(final PGPSignature pSignature, final InputStream pClearText) {
		ByteArrayOutputStream lLineOut = new ByteArrayOutputStream();
		int lLookAhead;
		boolean lReturn = false;
		try {
			lLookAhead = readInputLine(lLineOut, pClearText);

			processLine(pSignature, lLineOut.toByteArray());

			if (lLookAhead != -1) {
				do {
					lLookAhead = readInputLine(lLineOut, lLookAhead, pClearText);

					pSignature.update((byte) '\r');
					pSignature.update((byte) '\n');

					processLine(pSignature, lLineOut.toByteArray());
				} while (lLookAhead != -1);
			}
			lReturn = pSignature.verify();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (PGPException e) {
			e.printStackTrace();
		}
		return lReturn;
	}

	private static int readInputLine(final ByteArrayOutputStream pOut, int pLookAhead, final InputStream pIn) throws IOException {
		pOut.reset();

		int lChar = pLookAhead;

		do {
			pOut.write(lChar);
			if ((lChar == '\r') || (lChar == '\n')) {
				pLookAhead = readPassedEOL(pOut, lChar, pIn);
				break;
			}
		} while ((lChar = pIn.read()) >= 0);

		return pLookAhead;
	}
	private static int readInputLine(final ByteArrayOutputStream pOut, final InputStream pIn) throws IOException {
		pOut.reset();

		int lLookAhead = -1;
		int lChar;

		while ((lChar = pIn.read()) >= 0) {
			pOut.write(lChar);
			if ((lChar == '\r') || (lChar == '\n')) {
				lLookAhead = readPassedEOL(pOut, lChar, pIn);
				break;
			}
		}

		return lLookAhead;
	}

	private static int readPassedEOL(final ByteArrayOutputStream pOut, final int pLastCh, final InputStream pIn) throws IOException {
		int lLookAhead = pIn.read();

		if ((pLastCh == '\r') && (lLookAhead == '\n')) {
			pOut.write(lLookAhead);
			lLookAhead = pIn.read();
		}

		return lLookAhead;
	}

	private static void processLine(final PGPSignature pSignature, final byte[] pLine) throws SignatureException, IOException {
		int length = getLengthWithoutWhiteSpace(pLine);
		if (length > 0) {
			pSignature.update(pLine, 0, length);
		}
	}

	private static int getLengthWithoutWhiteSpace(final byte[] pLine) {
		int lEnd = pLine.length - 1;

		while ((lEnd >= 0) && isWhiteSpace(pLine[lEnd])) {
			lEnd--;
		}

		return lEnd + 1;
	}

	private static boolean isWhiteSpace(final byte pByte) {
		return (pByte == '\r') || (pByte == '\n') || (pByte == '\t') || (pByte == ' ');
	}
}

