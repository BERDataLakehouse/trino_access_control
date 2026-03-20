package us.kbase.trino;

import io.trino.spi.Plugin;
import io.trino.spi.security.SystemAccessControlFactory;

import java.util.List;

/**
 * Trino plugin entry point for BERDL namespace isolation access control.
 *
 * <p>Registers the {@link BerdlAccessControlFactory} so Trino can instantiate
 * the access control via {@code access-control.name=berdl-namespace-isolation}.
 */
public class BerdlAccessControlPlugin implements Plugin {

    @Override
    public Iterable<SystemAccessControlFactory> getSystemAccessControlFactories() {
        return List.of(new BerdlAccessControlFactory());
    }
}
