package at.bostijancic.vertx.jwt;

import org.vertx.java.core.json.JsonObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Helper class which is used to create and verify the JWT.
 *
 * @author emil.bostijancic@gmail.com 2015-01-01
 */
public class JwtUtil {

    public static final String UTF_8 = "UTF-8";
    private static String BASE64_HEADER = "";

    static {
        final JsonObject header = new JsonObject();
        header.putString("typ", "JWT");
        header.putString("alg", "HS256");

        BASE64_HEADER = encode(header);
    }


    /**
     * Method will base64 encode the payload.
     *
     * @param payload JWT header.
     * @return BASE64 encoded string of the JWT header.
     */
    public static String encode(JsonObject payload) {

        // if no payload was given return null.
        if (payload == null) {
            return null;
        }

        try {
            final byte[] payloadBytes = payload.toString().getBytes(UTF_8);
            final byte[] encodedPayload = Base64.getEncoder().encode(payloadBytes);

            return new String(encodedPayload, UTF_8);
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * decode will decode an BASE64 encoded hash into
     * a JsonObject.
     *
     * @param hash BASE64 encoded JSON object.
     * @return decoded JSON object.
     */
    public static JsonObject decode(String hash) {
        if (hash == null) {
            return null;
        }

        try {
            final byte[] decoded = Base64.getDecoder().decode(hash.getBytes(UTF_8));
            return new JsonObject(new String(decoded, UTF_8));
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    /**
     * Method will return a signed JWT token for given payload (JsonObject)
     * and given secret key. It will used the HmacSHA256 algorithm.
     *
     * @param payload   Payload to put into the token.
     * @param secretKey Secret key to use for the encryption.
     * @return signed JWT token.
     */
    public static String signToken(JsonObject payload, String secretKey) {
        if (payload == null || secretKey == null) {
            return null;
        }

        try {
            final byte[] payloadBytes = payload.toString().getBytes(UTF_8);

            final Mac hmac = initMac(secretKey);

            // create the signature.
            final String signature = Base64.getEncoder().encodeToString(hmac.doFinal(payloadBytes));

            // return JWT complaint token.
            return BASE64_HEADER + "." + encode(payload) + "." + signature;
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    private static Mac initMac(String secretKey) {
        final String algorithm = "HmacSHA256";

        final Mac hmac;
        try {
            hmac = Mac.getInstance(algorithm);
            final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(UTF_8), algorithm);
            hmac.init(secretKeySpec);
        } catch (UnsupportedEncodingException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (InvalidKeyException e) {
            return null;
        }
        return hmac;
    }

    /**
     * Method will verify if the given token is valid. It will create a signed
     * token using the payload from the token and compare it to the given token.
     *
     * @param token     JWT to verify
     * @param secretKey Secret key used
     * @return true if token is valid.
     */
    public static boolean verifyToken(String token, String secretKey) {
        final String encodedPayload = token.split("\\.")[1];
        final JsonObject payload = decode(encodedPayload);

        return token.equals(signToken(payload, secretKey));
    }
}
