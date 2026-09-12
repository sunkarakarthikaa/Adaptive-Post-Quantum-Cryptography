import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * CryptoService
 * --------------
 * Implements the hybrid encryption primitive stack:
 *   - Kyber (CRYSTALS-Kyber / precursor to NIST FIPS 203 ML-KEM) as the
 *     post-quantum Key Encapsulation Mechanism (KEM), used to protect the
 *     AES session key.
 *   - AES-256-GCM as the symmetric cipher for the actual sensor payload
 *     (fast, authenticated encryption, well suited for bulk data).
 *
 * NOTE ON TERMINOLOGY: Bouncy Castle 1.77's `pqc.crypto.crystals.kyber`
 * package implements the CRYSTALS-Kyber algorithm as submitted to/selected
 * by NIST's PQC standardization process, prior to the final FIPS 203
 * (ML-KEM) renaming/parameter finalization. For a paper, cite this
 * precisely as "CRYSTALS-Kyber (NIST PQC Round 3 selection, precursor to
 * ML-KEM/FIPS 203)" rather than claiming FIPS 203 compliance outright -
 * that distinction matters for reviewers.
 *
 * WORKFLOW (per session):
 *   Cloud server:  generate Kyber keypair (pubKey, privKey) -> publish pubKey
 *   Device:        KyberKEMGenerator.generateEncapsulated(pubKey)
 *                    -> {sharedSecret, encapsulation}
 *                  derive AES-256 key from sharedSecret
 *                  AES-256-GCM encrypt(payload, aesKey) -> {ciphertext, iv, tag}
 *                  send {encapsulation, ciphertext, iv} to server
 *   Server:        KyberKEMExtractor.extractSecret(encapsulation) -> sharedSecret
 *                  derive same AES-256 key from sharedSecret
 *                  AES-256-GCM decrypt(ciphertext, iv, aesKey) -> payload
 */
public class CryptoService {

    private static final SecureRandom RNG = new SecureRandom();
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    /** Result of the device-side encrypt step - everything sent "over the wire". */
    public static class Transmission {
        public final byte[] kyberEncapsulation; // Kyber ciphertext (the encapsulated key)
        public final byte[] aesCiphertext;      // AES-GCM ciphertext (includes auth tag)
        public final byte[] iv;                 // AES-GCM IV/nonce
        public Transmission(byte[] kyberEncapsulation, byte[] aesCiphertext, byte[] iv) {
            this.kyberEncapsulation = kyberEncapsulation;
            this.aesCiphertext = aesCiphertext;
            this.iv = iv;
        }
    }

    /** Fine-grained timing breakdown for one device-side encrypt call, in nanoseconds. */
    public static class DeviceTiming {
        public final Transmission transmission;
        public final long kyberEncapsulateNanos;
        public final long aesEncryptNanos;
        public DeviceTiming(Transmission transmission, long kyberEncapsulateNanos, long aesEncryptNanos) {
            this.transmission = transmission;
            this.kyberEncapsulateNanos = kyberEncapsulateNanos;
            this.aesEncryptNanos = aesEncryptNanos;
        }
    }

    /** Fine-grained timing breakdown for one server-side decrypt call, in nanoseconds. */
    public static class ServerTiming {
        public final byte[] payload;
        public final long kyberDecapsulateNanos;
        public final long aesDecryptNanos;
        public ServerTiming(byte[] payload, long kyberDecapsulateNanos, long aesDecryptNanos) {
            this.payload = payload;
            this.kyberDecapsulateNanos = kyberDecapsulateNanos;
            this.aesDecryptNanos = aesDecryptNanos;
        }
    }

    /** Cloud-side long-lived Kyber identity for a given security level. */
    public static class ServerIdentity {
        public final KyberPublicKeyParameters publicKey;
        public final KyberPrivateKeyParameters privateKey;
        public ServerIdentity(KyberPublicKeyParameters pub, KyberPrivateKeyParameters priv) {
            this.publicKey = pub;
            this.privateKey = priv;
        }
    }

    /** Generates a fresh Kyber keypair for the cloud server at the given security level. */
    public ServerIdentity generateServerIdentity(PolicyEngine.SecurityLevel level) {
        KyberKeyPairGenerator gen = new KyberKeyPairGenerator();
        gen.init(new KyberKeyGenerationParameters(RNG, level.bcParams));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        return new ServerIdentity(
                (KyberPublicKeyParameters) pair.getPublic(),
                (KyberPrivateKeyParameters) pair.getPrivate());
    }

    /**
     * Device-side operation: encapsulate a fresh shared secret against the
     * server's Kyber public key, derive an AES-256 key from it, and
     * AES-256-GCM encrypt the sensor payload. Returns a fine-grained timing
     * breakdown (Kyber encapsulation cost vs. AES cost) - this split is
     * what lets the evaluation section report "PQC overhead" separately
     * from baseline symmetric-crypto cost, which is the number reviewers
     * actually want to see.
     */
    public DeviceTiming encryptForTransmission(byte[] payload, KyberPublicKeyParameters serverPublicKey)
            throws Exception {
        // 1. Kyber encapsulation -> shared secret + encapsulation (Kyber ciphertext)
        long k0 = System.nanoTime();
        KyberKEMGenerator kemGen = new KyberKEMGenerator(RNG);
        SecretWithEncapsulation encap = kemGen.generateEncapsulated(serverPublicKey);
        byte[] sharedSecret = encap.getSecret();
        byte[] kyberCiphertext = encap.getEncapsulation();
        long k1 = System.nanoTime();

        // 2. Derive AES-256 key from the Kyber shared secret (counted as part
        //    of the Kyber-side cost since it's a direct dependency of the KEM output)
        byte[] aesKeyBytes = deriveAesKey(sharedSecret);
        long k2 = System.nanoTime();

        // 3. AES-256-GCM encrypt the payload
        byte[] iv = new byte[GCM_IV_BYTES];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(payload);
        long k3 = System.nanoTime();

        Transmission tx = new Transmission(kyberCiphertext, ciphertext, iv);
        return new DeviceTiming(tx, (k2 - k0), (k3 - k2));
    }

    /**
     * Server-side operation: decapsulate the shared secret using the
     * server's Kyber private key, re-derive the AES-256 key, and decrypt.
     * Returns the same kind of fine-grained timing breakdown as the device side.
     */
    public ServerTiming decryptTransmission(Transmission tx, KyberPrivateKeyParameters serverPrivateKey)
            throws Exception {
        // 1. Kyber decapsulation -> recover the same shared secret
        long k0 = System.nanoTime();
        KyberKEMExtractor extractor = new KyberKEMExtractor(serverPrivateKey);
        byte[] sharedSecret = extractor.extractSecret(tx.kyberEncapsulation);
        byte[] aesKeyBytes = deriveAesKey(sharedSecret);
        long k1 = System.nanoTime();

        // 2. AES-256-GCM decrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, tx.iv));
        byte[] plaintext = cipher.doFinal(tx.aesCiphertext);
        long k2 = System.nanoTime();

        return new ServerTiming(plaintext, (k1 - k0), (k2 - k1));
    }

    /**
     * Derives a 256-bit AES key from the raw Kyber shared secret using
     * SHA-256 as a simple KDF. NOTE for the paper: a production system
     * should use a proper KDF (e.g. HKDF) with context/label binding;
     * SHA-256 direct-hash is used here for simplicity in the v1 minimal
     * build and should be flagged as a known simplification, not a
     * cryptographic design recommendation.
     */
    private byte[] deriveAesKey(byte[] sharedSecret) throws Exception {
        java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sharedSecret);
        return Arrays.copyOf(hash, 32); // 256-bit AES key
    }
}
