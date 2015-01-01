package at.bostijancic.vertx.jwt;

import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonObject;
import org.vertx.java.platform.Verticle;

/**
 * JsonWebTokenValidator is a verticle used to create and
 * verify JWT (json web tokens) using HMAC SHA256 algorithm).
 * <p/>
 * The secret key is obtained from the config.json file.
 *
 * @author emil.bostijancic@gmail.com 2015-01-01.
 */
public class JsonWebTokenValidator extends Verticle {
    public static final String SIGN_MESSAGE = "jwt-sign-message";
    public static final String VERIFY_MESSAGE = "jwt-verify-message";
    public static final String SECRET_KEY_JSON_FIELD = "jwt_secret_key";

    @Override
    public void start() {

        // get secret key from config.json
        final String key = container.config().getString(SECRET_KEY_JSON_FIELD);

        assert key != null && !key.equals("");

        vertx.eventBus().registerHandler(SIGN_MESSAGE, new Handler<Message>() {
            @Override
            public void handle(Message event) {
                final JsonObject payload = (JsonObject) event.body();

                // reply with signed token for given payload and secret key.
                // the header is fixed.
                event.reply(JwtUtil.signToken(payload, key));
            }
        });

        // verify token when verify-message is received.
        vertx.eventBus().registerHandler(VERIFY_MESSAGE, new Handler<Message>() {
            @Override
            public void handle(Message event) {
                // reply with true if token is verified.
                event.reply(JwtUtil.verifyToken((String) event.body(), key));
            }
        });
    }
}
