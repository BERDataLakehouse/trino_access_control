package us.kbase.trino;

import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemAccessControlFactory;

import java.util.Map;

// SystemAccessControlContext is required by the factory interface in Trino 479+

/**
 * Factory for creating {@link BerdlSystemAccessControl} instances.
 *
 * <p>Configuration properties (set in {@code access-control.properties}):
 * <ul>
 *   <li>{@code shared.catalogs} — comma-separated catalog names visible to all users
 *       (default: {@code delta,hive,system})</li>
 *   <li>{@code shared.schemas} — comma-separated schema names visible to all users
 *       (default: {@code information_schema,default})</li>
 *   <li>{@code unfiltered.catalogs} — catalogs where schema filtering is skipped entirely
 *       (default: {@code system})</li>
 * </ul>
 */
public class BerdlAccessControlFactory implements SystemAccessControlFactory {

    @Override
    public String getName() {
        return "berdl-namespace-isolation";
    }

    @Override
    public SystemAccessControl create(Map<String, String> config,
            SystemAccessControlContext context) {
        return new BerdlSystemAccessControl(config);
    }
}
