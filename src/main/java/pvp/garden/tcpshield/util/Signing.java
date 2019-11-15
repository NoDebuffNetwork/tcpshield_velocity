package pvp.garden.tcpshield.util;

import com.google.common.io.ByteStreams;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Signing {
    private static PublicKey key;

    public static void initialize()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = ByteStreams.toByteArray(Signing.class.getResourceAsStream("/signing_pub.key"));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        KeyFactory factory = KeyFactory.getInstance("EC");

        key = factory.generatePublic(spec);
    }

    public static boolean verify(byte[] data, String encoded)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] decoded = Base64.getDecoder().decode(encoded);
        Signature signature = Signature.getInstance("SHA512withECDSA");

        signature.initVerify(key);
        signature.update(data);

        return signature.verify(decoded);
    }
}
