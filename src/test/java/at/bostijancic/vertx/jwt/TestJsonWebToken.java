package at.bostijancic.vertx.jwt;

import org.junit.Test;
import org.vertx.java.core.AsyncResult;
import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonObject;
import org.vertx.testtools.TestVerticle;

import static org.vertx.testtools.VertxAssert.fail;
import static org.vertx.testtools.VertxAssert.testComplete;

/**
 * Test should verify that verticle is working correctly.
 *
 * @author emil.bostijancic@gmail.com 2015-01-01.
 */
public class TestJsonWebToken extends TestVerticle {
    private static final String SECRET_KEY = "ABCDEFGHI32";

    @Override
    public void start() {
        initialize();

        // set the secret key by using the config.json.
        final JsonObject config = new JsonObject();
        config.putString(JsonWebTokenValidator.SECRET_KEY_JSON_FIELD, SECRET_KEY);

        // deploy verticle manually
        container.deployVerticle(JsonWebTokenValidator.class.getName(), config, new Handler<AsyncResult<String>>() {
            @Override
            public void handle(AsyncResult<String> event) {
                startTests();
            }
        });
    }


    @Test
    public void shouldSignToken() {
        vertx.eventBus().send(JsonWebTokenValidator.SIGN_MESSAGE, samplePayload(), new Handler<Message>() {
            @Override
            public void handle(Message event) {
                final String token = (String) event.body();

                if (token != null && !token.isEmpty()) {
                    testComplete();
                } else {
                    fail("incorrect token");
                }
            }
        });
    }

    private JsonObject samplePayload() {
        final JsonObject payload = new JsonObject();

        payload.putString("user", "emil");
        payload.putNumber("age", 32);

        return payload;
    }

    @Test
    public void shouldVerifySignedToken() {

        // create an signed token.
        final String token = JwtUtil.signToken(samplePayload(), SECRET_KEY);

        // verify signed token.
        vertx.eventBus().send(JsonWebTokenValidator.VERIFY_MESSAGE, token, new Handler<Message>() {
            @Override
            public void handle(Message event) {
                final Boolean valid = (Boolean) event.body();

                if (valid) {
                    testComplete();
                } else {
                    fail();
                }
            }
        });
    }
}
