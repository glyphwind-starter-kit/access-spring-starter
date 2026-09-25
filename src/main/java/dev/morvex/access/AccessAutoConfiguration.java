package dev.morvex.access;

import dev.morvex.access.gateway.GatewaySigner;
import dev.morvex.access.web.AccessDeniedAdvice;
import dev.morvex.access.web.AccessInterceptor;
import dev.morvex.access.web.CallerArgumentResolver;
import dev.morvex.access.web.CallerFilter;
import java.time.Clock;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Wires the caller filter, the access interceptor and the {@code Caller} argument resolver.
 * Fails fast at start-up when the gateway secret is required but missing, so a deployed
 * service can never silently run in "trust every header" mode.
 */
@AutoConfiguration
@EnableConfigurationProperties(AccessProperties.class)
@Import(AccessDeniedAdvice.class)
public class AccessAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AccessAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public Clock accessClock() {
        return Clock.systemUTC();
    }

    @Bean
    public FilterRegistrationBean<CallerFilter> callerFilter(AccessProperties properties, Clock accessClock) {
        AccessProperties.Gateway gateway = properties.gateway();
        GatewaySigner signer = null;
        if (gateway.required()) {
            if (gateway.secret() == null || gateway.secret().isBlank()) {
                throw new IllegalStateException(
                        "access.gateway.secret is not set; set it (shared with the api-gateway) or, for a local run"
                                + " without a gateway only, access.gateway.required=false");
            }
            signer = new GatewaySigner(gateway.secret());
        } else {
            log.warn("access.gateway.required=false: identity headers are trusted WITHOUT a signature; local runs only");
        }
        FilterRegistrationBean<CallerFilter> registration =
                new FilterRegistrationBean<>(new CallerFilter(signer, gateway, accessClock));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 100);
        return registration;
    }

    @Bean
    public WebMvcConfigurer accessWebMvcConfigurer(AccessProperties properties) {
        AccessInterceptor interceptor = new AccessInterceptor(properties.defaultPolicy());
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(interceptor).addPathPatterns(properties.pathPatterns());
            }

            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(new CallerArgumentResolver());
            }
        };
    }
}
