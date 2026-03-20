/*
 * BERDL Namespace Isolation Access Control for Trino
 *
 * Enforces the same u_{username}__* namespace isolation that the Spark Connect
 * NamespaceValidationInterceptor provides, but at the Trino query engine level.
 *
 * Configuration (in access-control.properties):
 *   access-control.name=berdl-namespace-isolation
 *   shared.catalogs=delta,hive,system
 *   shared.schemas=information_schema,default
 *   unfiltered.catalogs=system
 */
package us.kbase.trino;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;

import io.trino.spi.QueryId;
import io.trino.spi.security.Identity;

import java.security.Principal;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Trino SystemAccessControl that enforces BERDL namespace isolation.
 *
 * <p>Users can only see and access:
 * <ul>
 *   <li>Catalogs matching {@code u_{username}_*} (their own) and shared catalogs</li>
 *   <li>Schemas matching {@code u_{username}__*} (their own) and shared schemas</li>
 * </ul>
 *
 * <p>This replaces the static file-based rules.json with dynamic, username-derived
 * access control — no sync job or per-user configuration needed.
 */
public class BerdlSystemAccessControl implements SystemAccessControl {

    private static final Logger LOGGER = Logger.getLogger(BerdlSystemAccessControl.class.getName());

    /** Prefix for user-owned namespaces: "u_" */
    private static final String USER_PREFIX = "u_";

    /** Separator between username and catalog suffix: "_" (e.g., u_alice_lake) */
    private static final String CATALOG_SEPARATOR = "_";

    /** Separator between username and schema name: "__" (e.g., u_alice__my_db) */
    private static final String SCHEMA_SEPARATOR = "__";

    private final Set<String> sharedCatalogs;
    private final Set<String> sharedSchemas;
    private final Set<String> unfilteredCatalogs;

    public BerdlSystemAccessControl(Map<String, String> config) {
        this.sharedCatalogs = parseSet(config.getOrDefault("shared.catalogs", "delta,hive,system"));
        this.sharedSchemas = parseSet(config.getOrDefault("shared.schemas", "information_schema,default"));
        this.unfilteredCatalogs = parseSet(config.getOrDefault("unfiltered.catalogs", "system"));

        LOGGER.info("BERDL Namespace Isolation initialized: " +
                "sharedCatalogs=" + sharedCatalogs +
                ", sharedSchemas=" + sharedSchemas +
                ", unfilteredCatalogs=" + unfilteredCatalogs);
    }

    // -----------------------------------------------------------------------
    // Identity and session — must be explicitly allowed (defaults to deny)
    // -----------------------------------------------------------------------

    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName) {
        // Allow all users to connect. Authentication (KBase token validation)
        // is handled by a separate PasswordAuthenticator plugin in production.
    }

    @Override
    public void checkCanExecuteQuery(Identity identity, QueryId queryId) {
        // Allow all authenticated users to execute queries.
    }

    @Override
    public void checkCanReadSystemInformation(Identity identity) {
        // Allow reading system info (needed for SHOW CATALOGS, etc.).
    }

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, QueryId queryId,
            String propertyName) {
        // Allow setting session properties.
    }


    // -----------------------------------------------------------------------
    // Catalog access gate — must return true for any catalog operations
    // -----------------------------------------------------------------------

    @Override
    public boolean canAccessCatalog(SystemSecurityContext context, String catalogName) {
        return isCatalogAllowed(getUser(context), catalogName);
    }

    // -----------------------------------------------------------------------
    // Show/describe checks — must be explicitly allowed (defaults deny)
    // -----------------------------------------------------------------------

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
        // Allow — filterSchemas handles what's visible.
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
        checkSchemaAccess(context, schema.getCatalogName(), schema.getSchemaName(), "show tables in");
    }

    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table) {
        // Allow — column access controlled by checkCanSelectFromColumns.
    }

    @Override
    public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        checkSchemaAccess(context, schema.getCatalogName(), schema.getSchemaName(), "show create");
    }

    @Override
    public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "show create");
    }

    // -----------------------------------------------------------------------
    // Visibility filtering — controls what appears in SHOW CATALOGS/SCHEMAS/TABLES
    // -----------------------------------------------------------------------

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
        String user = getUser(context);
        return catalogs.stream()
                .filter(catalog -> isCatalogAllowed(user, catalog))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName,
            Set<String> schemaNames) {
        if (unfilteredCatalogs.contains(catalogName.toLowerCase(Locale.ROOT))) {
            return schemaNames;
        }
        String user = getUser(context);
        return schemaNames.stream()
                .filter(schema -> isSchemaAllowed(user, schema))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName,
            Set<SchemaTableName> tableNames) {
        if (unfilteredCatalogs.contains(catalogName.toLowerCase(Locale.ROOT))) {
            return tableNames;
        }
        String user = getUser(context);
        return tableNames.stream()
                .filter(table -> isSchemaAllowed(user, table.getSchemaName()))
                .collect(Collectors.toSet());
    }

    // -----------------------------------------------------------------------
    // Data access checks — enforces SELECT/INSERT/UPDATE/DELETE restrictions
    // -----------------------------------------------------------------------

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context,
            CatalogSchemaTableName table, Set<String> columns) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "select from");
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context,
            CatalogSchemaTableName table) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "insert into");
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context,
            CatalogSchemaTableName table) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "delete from");
    }

    @Override
    public void checkCanUpdateTableColumns(SystemSecurityContext context,
            CatalogSchemaTableName table, Set<String> updatedColumnNames) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "update");
    }

    // -----------------------------------------------------------------------
    // DDL checks — restricts CREATE/DROP SCHEMA and CREATE/DROP/RENAME TABLE
    // -----------------------------------------------------------------------

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema,
            Map<String, Object> properties) {
        String user = getUser(context);
        String schemaName = schema.getSchemaName().toLowerCase(Locale.ROOT);
        String userSchemaPrefix = USER_PREFIX + user.toLowerCase(Locale.ROOT) + SCHEMA_SEPARATOR;

        if (!schemaName.startsWith(userSchemaPrefix)) {
            throw new AccessDeniedException(
                    "Schema name '" + schema.getSchemaName() + "' is not allowed. " +
                    "Schema names must start with '" + userSchemaPrefix + "'.");
        }
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        checkSchemaAccess(context, schema.getCatalogName(), schema.getSchemaName(), "drop");
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context,
            CatalogSchemaTableName table, Map<String, Object> properties) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "create table in");
    }

    @Override
    public void checkCanDropTable(SystemSecurityContext context,
            CatalogSchemaTableName table) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "drop table in");
    }

    @Override
    public void checkCanRenameTable(SystemSecurityContext context,
            CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
        checkSchemaAccess(context, table.getCatalogName(),
                table.getSchemaTableName().getSchemaName(), "rename table in");
        checkSchemaAccess(context, newTable.getCatalogName(),
                newTable.getSchemaTableName().getSchemaName(), "rename table to");
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Check if the user is allowed to access the given schema in the given catalog.
     * Throws AccessDeniedException if denied.
     */
    private void checkSchemaAccess(SystemSecurityContext context, String catalogName,
            String schemaName, String operation) {
        if (unfilteredCatalogs.contains(catalogName.toLowerCase(Locale.ROOT))) {
            return;
        }
        String user = getUser(context);
        if (!isSchemaAllowed(user, schemaName)) {
            throw new AccessDeniedException(
                    "User '" + user + "' cannot " + operation + " schema '" + schemaName + "'. " +
                    "Access is limited to schemas matching '" +
                    USER_PREFIX + user + SCHEMA_SEPARATOR + "*'.");
        }
    }

    /**
     * Check if a catalog is accessible to the user.
     *
     * <p>Allowed if:
     * <ul>
     *   <li>Catalog starts with {@code u_{user}_} (user's own catalog)</li>
     *   <li>Catalog is in the shared catalogs list</li>
     * </ul>
     */
    private boolean isCatalogAllowed(String user, String catalogName) {
        String catalog = catalogName.toLowerCase(Locale.ROOT);
        String userCatalogPrefix = USER_PREFIX + user.toLowerCase(Locale.ROOT) + CATALOG_SEPARATOR;
        return catalog.startsWith(userCatalogPrefix) || sharedCatalogs.contains(catalog);
    }

    /**
     * Check if a schema is accessible to the user.
     *
     * <p>Allowed if:
     * <ul>
     *   <li>Schema starts with {@code u_{user}__} (user's own namespace)</li>
     *   <li>Schema starts with {@code globalusers_} (shared tenant namespace)</li>
     *   <li>Schema is in the shared schemas list (information_schema, default)</li>
     * </ul>
     */
    private boolean isSchemaAllowed(String user, String schemaName) {
        String schema = schemaName.toLowerCase(Locale.ROOT);
        String userSchemaPrefix = USER_PREFIX + user.toLowerCase(Locale.ROOT) + SCHEMA_SEPARATOR;
        return schema.startsWith(userSchemaPrefix)
                || schema.startsWith("globalusers_")
                || sharedSchemas.contains(schema);
    }

    private static String getUser(SystemSecurityContext context) {
        return context.getIdentity().getUser();
    }

    private static Set<String> parseSet(String csv) {
        return Set.of(csv.split(",")).stream()
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
