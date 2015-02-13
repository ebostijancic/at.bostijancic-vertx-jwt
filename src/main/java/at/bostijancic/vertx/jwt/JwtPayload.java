package at.bostijancic.vertx.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.vertx.java.core.json.JsonObject;

import java.util.Date;

/**
 * Object representing the payload.
 *
 * @author emil.bostijancic@gmail.com 2015-02-13
 */
public class JwtPayload extends JsonObject {

    @JsonProperty("iss")
    private String issuer;

    @JsonProperty("sub")
    private String subject;

    @JsonProperty("aud")
    private String audience;

    @JsonProperty("exp")
    private Date expirationTime;

    @JsonProperty("nbf")
    private Date notBefore;

    @JsonProperty("iat")
    private Date issuedAt;

    public JwtPayload setIssuer(String issuer) {
        putString("iss", issuer);
        return this;
    }

    public JwtPayload setSubject(String subject) {
        putString("sub", subject);
        return this;
    }

    public JwtPayload setAudience(String audience) {
        putString("aud", audience);
        return this;
    }

    public JwtPayload setExpirationTime(Date expirationTime) {
        putNumber("exp", expirationTime.getTime());
        return this;
    }

    public JwtPayload setExpirationTime(int seconds) {
        putNumber("exp", seconds);
        return this;
    }

    public JwtPayload setNotBefore(Date notBefore) {
        putNumber("nbf", notBefore.getTime());
        return this;
    }

    public JwtPayload setIssuedAt(Date issuedAt) {
        putNumber("iat", issuedAt.getTime());
        return this;
    }
}
