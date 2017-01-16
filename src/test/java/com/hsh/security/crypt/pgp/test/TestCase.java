package com.hsh.security.crypt.pgp.test;

import static org.junit.Assert.fail;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.junit.Test;

import com.hsh.security.crypt.pgp.conf.FilePath;
import com.hsh.security.crypt.pgp.io.PGPInputStream;
import com.hsh.security.crypt.pgp.io.PGPOutputStream;
import com.hsh.security.crypt.pgp.io.PGPStreamFactory;

public class TestCase {

	private static final String	PASSPHRASE_ALICE	= "changeit";
	private static final String	PASSPHRASE_BOB	= "changeit";

	public static void testEncrypt(final String pInFilePath, final String pOutFilePath, final String pSecKeyFilePath, final String[] pPubKeyFilePaths, final char[] pPassphrase, 
			final boolean pArmored, final boolean pCompressed) throws Exception {
		File lInFile = new File(TestCase.class.getClassLoader().getResource(pInFilePath).getFile());
		File lOutFile = new File(TestCase.class.getClassLoader().getResource("").getFile()+pOutFilePath);

		InputStream in = new BufferedInputStream(lInFile.toURL().openStream());
		OutputStream out = new BufferedOutputStream(new FileOutputStream(lOutFile));

		PGPSecretKeyRingCollection lSecKeyringCollection = null;
		PGPPublicKeyRingCollection lPubKeyringCollection = null;
		if (pSecKeyFilePath != null) {
			InputStream lInSecretKeyStream = TestCase.class.getClassLoader().getResourceAsStream(pSecKeyFilePath);
			lSecKeyringCollection = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(lInSecretKeyStream));
			lInSecretKeyStream.close();
		}

		//		if (pPubKeyFilePath != null) {
		//			InputStream lInPublicKeyStream = TestCase.class.getClassLoader().getResourceAsStream(pPubKeyFilePath);
		//			lPubKeyringCollection = new BcPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(lInPublicKeyStream));
		//			lInPublicKeyStream.close();

		if (pPubKeyFilePaths != null) {
			for (String lPubKeyFilePath : pPubKeyFilePaths) {
				InputStream lInPublicKeyStream = TestCase.class.getClassLoader().getResourceAsStream(lPubKeyFilePath);
				BcPGPPublicKeyRingCollection lLocalKeyRingCollec = new BcPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(lInPublicKeyStream));
				if (lPubKeyringCollection == null) {
					lPubKeyringCollection = lLocalKeyRingCollec;
				} else {
					Iterator iter = lLocalKeyRingCollec.getKeyRings();
					while (iter.hasNext()) {
						PGPPublicKeyRing lPubKeyRing = (PGPPublicKeyRing) iter.next();
						lPubKeyringCollection = PGPPublicKeyRingCollection.addPublicKeyRing(lPubKeyringCollection, lPubKeyRing);
					}
				}
				lInPublicKeyStream.close();
			}
		}


		PGPStreamFactory streamFactory = PGPStreamFactory.getInstance(lPubKeyringCollection, lSecKeyringCollection, pPassphrase);
		if (!pArmored) {
			streamFactory.disableArmoring();
		}
		if (!pCompressed) {
			streamFactory.disableCompression();
		}
		if (pPubKeyFilePaths == null) {
			streamFactory.disableEncyption();
		}
		OutputStream lCipheredStream = streamFactory.getPGPOutputStream(out, lInFile.getName());

		//		for (int i = in.read(); i >= 0; i = in.read()) {
		//			lCipheredStream.write(i);
		//		}

		byte[] buf = new byte[PGPOutputStream.getBufferSize()];
		int len;
		while ((len = in.read(buf)) > 0) {
			lCipheredStream.write(buf, 0, len);
		}

		lCipheredStream.flush();
		lCipheredStream.close();

		in.close();
	}

	public static void testDecrypt(final String pFilePath, final String pSecKeyFilePath, final String pPubKeyFilePath, final char[] pPassphrase) throws Exception {

		InputStream in = TestCase.class.getClassLoader().getResourceAsStream(pFilePath);
		in = new BufferedInputStream(in);
		OutputStream out = new ByteArrayOutputStream();

		PGPSecretKeyRingCollection lSecKeyringCollection = null;
		PGPPublicKeyRingCollection lPubKeyringCollection = null;
		if (pSecKeyFilePath != null) {
			InputStream lInSecretKeyStream = TestCase.class.getClassLoader().getResourceAsStream(pSecKeyFilePath);
			lSecKeyringCollection = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(lInSecretKeyStream));
			lInSecretKeyStream.close();
		}
		if (pPubKeyFilePath != null) {
			InputStream lInPublicKeyStream = TestCase.class.getClassLoader().getResourceAsStream(pPubKeyFilePath);
			lPubKeyringCollection = new BcPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(lInPublicKeyStream));
			lInPublicKeyStream.close();
		}

		PGPStreamFactory streamFactory = PGPStreamFactory.getInstance(lPubKeyringCollection, lSecKeyringCollection, pPassphrase);
		PGPInputStream lPgpInputStream = streamFactory.getPGPInputStream(in);

		byte[] lData = new byte[20];
		for (int lChar = lPgpInputStream.read(lData, 0, lData.length); lChar != -1; lChar = lPgpInputStream.read(lData, 0, lData.length)) {
			out.write(lData, 0, lChar);
		}

		out.flush();
		out.close();

		lPgpInputStream.close();

		if(lPgpInputStream.getReport().isSignedMessage()) {
			if (lPgpInputStream.getReport().isOnePassSignedMessage()) {
				if (!lPgpInputStream.getReport().isSignatureCheckSuccess()) {
					fail("Signature check failed");
				}
			} else {
				InputStream clearStream = new ByteArrayInputStream(((ByteArrayOutputStream)out).toByteArray());
				boolean signOk = lPgpInputStream.checkClearSignature(clearStream);
				System.out.println("Clear signature check is "+(signOk?"succefull":"failed"));
				if (!signOk) {
					fail("Clear Signature check failed");
				}
			}
		}


		System.out.println(((ByteArrayOutputStream)out).toString()+"\n\n\n");
	}
	/**/
	@Test
	public void testEncryptDecrypt_bob2alice_Ciphered() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_CIPHERED, null, new String[] {/*FilePath.PUB_KEY_BOB,*/ FilePath.PUB_KEY_ALICE}, null, false, false);
			testDecrypt(FilePath.BOB_2_ALICE_CIPHERED, FilePath.SEC_KEY_ALICE, null, PASSPHRASE_ALICE.toCharArray());
			testDecrypt(FilePath.BOB_2_ALICE_CIPHERED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CipheredArmored() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_CIPHERED_ARMORED, null, new String[] {FilePath.PUB_KEY_ALICE}, null, true, false);
			testDecrypt(FilePath.BOB_2_ALICE_CIPHERED_ARMORED, FilePath.SEC_KEY_ALICE, null, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CipheredSigned() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_CIPHERED_SIGNED, FilePath.SEC_KEY_BOB, new String[] {FilePath.PUB_KEY_ALICE}, PASSPHRASE_BOB.toCharArray(), false, false);
			testDecrypt(FilePath.BOB_2_ALICE_CIPHERED_SIGNED, FilePath.SEC_KEY_ALICE, FilePath.PUB_KEY_BOB, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CipheredSignedArmored() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_BOB, new String[] {FilePath.PUB_KEY_ALICE}, PASSPHRASE_BOB.toCharArray(), true, false);
			testDecrypt(FilePath.BOB_2_ALICE_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_ALICE, FilePath.PUB_KEY_BOB, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedSignedArmored() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_SIGNED_ARMORED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray(), true, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_SIGNED_ARMORED, null, FilePath.PUB_KEY_BOB, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedCiphered() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED, null, new String[] {FilePath.PUB_KEY_ALICE}, null, false, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED, FilePath.SEC_KEY_ALICE, null, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedCipheredArmored() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_ARMORED, null, new String[] {FilePath.PUB_KEY_ALICE}, null, true, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_ARMORED, FilePath.SEC_KEY_ALICE, null, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedCipheredSigned() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_SIGNED, FilePath.SEC_KEY_BOB, new String[] {FilePath.PUB_KEY_ALICE}, PASSPHRASE_BOB.toCharArray(), false, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_SIGNED, FilePath.SEC_KEY_ALICE, FilePath.PUB_KEY_BOB, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedCipheredSignedArmored() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_BOB, new String[] {FilePath.PUB_KEY_ALICE}, PASSPHRASE_BOB.toCharArray(), true, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_ALICE, FilePath.PUB_KEY_BOB, PASSPHRASE_ALICE.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_CompressedSigned() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_COMPRESSED_SIGNED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray(), false, true);
			testDecrypt(FilePath.BOB_2_ALICE_COMPRESSED_SIGNED, null, FilePath.PUB_KEY_BOB, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testEncryptDecrypt_bob2alice_Signed() {
		try {
			testEncrypt(FilePath.BOB_2_ALICE_TXT, FilePath.BOB_2_ALICE_SIGNED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray(), false, false);
			testDecrypt(FilePath.BOB_2_ALICE_SIGNED, null, FilePath.PUB_KEY_BOB, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	/**/








	/**/
	@Test
	public void testDecrypt_Alice2bob_Ciphered() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_CIPHERED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CipheredArmored() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_CIPHERED_ARMORED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CipheredSigned() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_CIPHERED_SIGNED, FilePath.SEC_KEY_BOB, FilePath.PUB_KEY_ALICE, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CipheredSignedArmored() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_BOB, FilePath.PUB_KEY_ALICE, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedSignedArmored() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_SIGNED_ARMORED, null, FilePath.PUB_KEY_ALICE, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedCiphered() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_CIPHERED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedCipheredArmored() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_CIPHERED_ARMORED, FilePath.SEC_KEY_BOB, null, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedCipheredSigned() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_CIPHERED_SIGNED, FilePath.SEC_KEY_BOB, FilePath.PUB_KEY_ALICE, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedCipheredSignedArmored() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_CIPHERED_SIGNED_ARMORED, FilePath.SEC_KEY_BOB, FilePath.PUB_KEY_ALICE, PASSPHRASE_BOB.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_CompressedSigned() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_COMPRESSED_SIGNED, null, FilePath.PUB_KEY_ALICE, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
	@Test
	public void testDecrypt_Alice2bob_Signed() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_SIGNED, null, FilePath.PUB_KEY_ALICE, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}

	/**/
	@Test
	public void testDecrypt_Alice2bob_ClearSigned() {
		try {
			testDecrypt(FilePath.ALICE_2_BOB_SIGNED_ARMORED, null, FilePath.PUB_KEY_ALICE, null);
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.toString());
		}
	}
}
