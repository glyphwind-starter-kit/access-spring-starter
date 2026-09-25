package dev.morvex.access;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class StartupTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AccessAutoConfiguration.class));

    @Test
    void refusesToStartWithoutTheGatewaySecret() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasMessageContaining("access.gateway.secret");
        });
    }

    @Test
    void refusesAShortSecret() {
        runner.withPropertyValues("access.gateway.secret=too-short").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasMessageContaining("at least 32 bytes");
        });
    }

    @Test
    void startsUnsignedOnlyWhenExplicitlyAllowed() {
        runner.withPropertyValues("access.gateway.required=false").run(context -> assertThat(context).hasNotFailed());
    }
}
