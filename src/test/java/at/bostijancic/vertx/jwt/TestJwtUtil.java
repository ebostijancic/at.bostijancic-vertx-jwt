package at.bostijancic.vertx.jwt;

import org.junit.Test;
import org.vertx.java.core.json.JsonObject;

import java.util.Date;

import static org.junit.Assert.*;

/**
 * Test should verify the JWT is created correctly.
 *
 * @author emil.bostijancic@gmail.com 2015-01-01.
 */
public class TestJwtUtil {

    private static final String SECRET_KEY = "Secret Key";

    @Test
    public void shouldGenerateHMacSha256Hash() {
        final JsonObject header = getHeader();
        final JsonObject payload = getPayload();

        final String token = JwtUtil.signToken(payload, SECRET_KEY);

        assertNotNull(token);

        final String headerTokenPart = token.split("\\.")[0];
        assertEquals(header, JwtUtil.decode(headerTokenPart));

        final String payloadTokenPart = token.split("\\.")[1];
        assertEquals(payload.toMap(), JwtUtil.decode(payloadTokenPart).toMap());

        final boolean isValid = JwtUtil.verifyToken(token, SECRET_KEY);
        assertTrue(isValid);

        final String modifiedToken = token.replaceFirst("a", "d");
        assertNotEquals(token, modifiedToken);

        assertFalse(JwtUtil.verifyToken(modifiedToken, SECRET_KEY));
        assertFalse(JwtUtil.verifyToken(token, "WRONG KEY"));

    }

    @Test
    public void shouldEncodeAndDecodeHeader() {
        final JsonObject header = getHeader();

        final String hash = JwtUtil.encode(header);
        assertNotNull(hash);
        assertNull(JwtUtil.encode(null));

        final JsonObject decodedHeader = JwtUtil.decode(hash);
        assertEquals(header, decodedHeader);
        assertNull(JwtUtil.decode(null));
    }

    @Test
    public void shouldEncodePayload() {
        final JsonObject payload = getPayload();

        final String hash = JwtUtil.encode(payload);
        assertNotNull(hash);

        final JsonObject decodedPayload = JwtUtil.decode(hash);
        assertEquals(payload.toMap(), decodedPayload.toMap());
    }

    private JsonObject getHeader() {
        final JsonObject header = new JsonObject();
        header.putString("typ", "JWT");
        header.putString("alg", "HS256");
        return header;
    }

    private JsonObject getPayload() {
        final JwtPayload payload = new JwtPayload();

        payload.setIssuer("emil");
        payload.setSubject("jwt");
        payload.setExpirationTime(3600);
        payload.setIssuedAt(new Date());
        payload.setNotBefore(new Date());
        payload.setAudience("all");

        System.out.println(payload.encodePrettily());
        return payload;
    }
}
