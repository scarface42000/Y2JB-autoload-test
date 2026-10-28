#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define APP_DB_PATH "/system_data/priv/mms/app.db"
#define APPINFO_DB_PATH "/system_data/priv/mms/appinfo.db"
#define BACKUP_DIR "/data/skyboz-loader"
#define APP_DB_BACKUP BACKUP_DIR "/app.db.before-skyboz-branding"
#define APP_DB_BACKUP_TEMP APP_DB_BACKUP ".tmp"
#define APPINFO_DB_BACKUP BACKUP_DIR "/appinfo.db.before-skyboz-branding"
#define APPINFO_DB_BACKUP_TEMP APPINFO_DB_BACKUP ".tmp"
#define SYSTEM_PARAM_PATH "/system_data/priv/appmeta/PPSA01650/param.json"
#define USER_PARAM_PATH "/user/appmeta/PPSA01650/param.json"
#define SYSTEM_PARAM_BACKUP BACKUP_DIR "/system-param.json.before-skyboz-branding"
#define SYSTEM_PARAM_BACKUP_TEMP SYSTEM_PARAM_BACKUP ".tmp"
#define USER_PARAM_BACKUP BACKUP_DIR "/user-param.json.before-skyboz-branding"
#define USER_PARAM_BACKUP_TEMP USER_PARAM_BACKUP ".tmp"
#define STATUS_PATH BACKUP_DIR "/icon-db.status"
#define STATUS_TEMP STATUS_PATH ".tmp"
#define ICON_PATH "/user/appmeta/PPSA01650/SKYBOZ_LOADER_icon0.png"
#define ICON_URI ICON_PATH "?ts=1"
#define TITLE_ID "PPSA01650"
#define NEW_TITLE "SKYBOZ LOADER"

static void write_status(const char *message)
{
    (void)mkdir(BACKUP_DIR, 0777);
    int fd = open(STATUS_TEMP, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;

    size_t length = strlen(message);
    size_t written = 0;
    while (written < length) {
        ssize_t amount = write(fd, message + written, length - written);
        if (amount <= 0) break;
        written += (size_t)amount;
    }
    if (written == length) (void)fsync(fd);
    (void)close(fd);
    if (written == length) (void)rename(STATUS_TEMP, STATUS_PATH);
    else (void)unlink(STATUS_TEMP);
}

static int database_integrity_ok(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return 0;
    }
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *result = sqlite3_column_text(stmt, 0);
        ok = result && strcmp((const char *)result, "ok") == 0;
    }
    if (stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok;
}

static int create_backup_if_missing(sqlite3 *source, const char *backup_path,
    const char *backup_temp, const char *database_name, char *error, size_t error_size)
{
    if (mkdir(BACKUP_DIR, 0777) != 0 && errno != EEXIST) {
        snprintf(error, error_size, "cannot create backup folder: %s", strerror(errno));
        return 0;
    }

    if (access(backup_path, F_OK) == 0) {
        if (database_integrity_ok(backup_path)) return 1;
        snprintf(error, error_size, "existing %s backup failed integrity check; refusing to overwrite it", database_name);
        return 0;
    }

    (void)unlink(backup_temp);
    sqlite3 *destination = NULL;
    int rc = sqlite3_open_v2(backup_temp, &destination,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot create %s backup: %s",
            database_name, destination ? sqlite3_errmsg(destination) : "sqlite open failed");
        if (destination) sqlite3_close(destination);
        (void)unlink(backup_temp);
        return 0;
    }

    sqlite3_busy_timeout(destination, 5000);
    sqlite3_backup *backup = sqlite3_backup_init(destination, "main", source, "main");
    if (!backup) {
        snprintf(error, error_size, "cannot start %s SQLite backup: %s", database_name, sqlite3_errmsg(destination));
        sqlite3_close(destination);
        (void)unlink(backup_temp);
        return 0;
    }

    int step_rc = SQLITE_OK;
    for (int attempt = 0; attempt < 100; attempt++) {
        step_rc = sqlite3_backup_step(backup, -1);
        if (step_rc == SQLITE_DONE) break;
        if (step_rc != SQLITE_OK && step_rc != SQLITE_BUSY && step_rc != SQLITE_LOCKED) break;
        usleep(50000);
    }
    int finish_rc = sqlite3_backup_finish(backup);
    int close_rc = sqlite3_close(destination);
    if (step_rc != SQLITE_DONE || finish_rc != SQLITE_OK || close_rc != SQLITE_OK ||
        !database_integrity_ok(backup_temp)) {
        snprintf(error, error_size, "%s backup did not pass integrity check", database_name);
        (void)unlink(backup_temp);
        return 0;
    }

    if (rename(backup_temp, backup_path) != 0) {
        snprintf(error, error_size, "cannot install %s backup: %s", database_name, strerror(errno));
        (void)unlink(backup_temp);
        return 0;
    }
    return 1;
}

static int find_local_concept_id(sqlite3 *db, char *out, size_t out_size, char *error, size_t error_size)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT localConceptId, json_valid(AppInfoJson) "
        "FROM tbl_contentinfo WHERE titleId = ? LIMIT 1";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "app.db schema mismatch: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, TITLE_ID, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        snprintf(error, error_size, "PPSA01650 row was not found in app.db");
        sqlite3_finalize(stmt);
        return 0;
    }
    const unsigned char *value = sqlite3_column_text(stmt, 0);
    if (!value || sqlite3_column_int(stmt, 1) != 1) {
        snprintf(error, error_size, "PPSA01650 app metadata is missing or invalid JSON");
        sqlite3_finalize(stmt);
        return 0;
    }
    snprintf(out, out_size, "%s", (const char *)value);
    sqlite3_finalize(stmt);
    return 1;
}

static int update_contentinfo(sqlite3 *db, char *error, size_t error_size)
{
    const char *sql =
        "UPDATE tbl_contentinfo SET titleName = ?, icon0Info = ?, "
        "AppInfoJson = json_set(json_set(json_set(AppInfoJson, '$.TITLE', ?), "
        "'$.TITLE_01', ?), '$.icon0Info', ?) WHERE titleId = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare tbl_contentinfo update: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, TITLE_ID, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update tbl_contentinfo: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return changes;
}

static int update_title_table(sqlite3 *db, const char *table, char *error, size_t error_size)
{
    char *sql = sqlite3_mprintf("UPDATE \"%w\" SET titleName = ? WHERE titleId = ?", table);
    if (!sql) {
        snprintf(error, error_size, "out of memory while preparing title metadata update");
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare %s update: %s", table, sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, TITLE_ID, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update %s: %s", table, sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return changes;
}

static int update_concept_table(sqlite3 *db, const char *table, const char *concept_id,
    char *error, size_t error_size)
{
    char *sql = sqlite3_mprintf(
        "UPDATE \"%w\" SET conceptName = ?, primaryTitleName = ?, icon0Info = ? WHERE localConceptId = ?",
        table);
    if (!sql) {
        snprintf(error, error_size, "out of memory while preparing concept metadata update");
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare %s update: %s", table, sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, concept_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update %s: %s", table, sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return changes;
}

static int update_per_account_tables(sqlite3 *db, const char *concept_id,
    char *error, size_t error_size)
{
    sqlite3_stmt *tables = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'tbl_iconinfo_*'",
            -1, &tables, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot inspect per-account title tables: %s", sqlite3_errmsg(db));
        return -1;
    }

    int total = 0;
    int rc;
    while ((rc = sqlite3_step(tables)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(tables, 0);
        if (!name) continue;
        int changed = update_title_table(db, (const char *)name, error, error_size);
        if (changed < 0) {
            sqlite3_finalize(tables);
            return -1;
        }
        total += changed;
    }
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot read per-account title tables: %s", sqlite3_errmsg(db));
        sqlite3_finalize(tables);
        return -1;
    }
    sqlite3_finalize(tables);

    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'tbl_concepticoninfo_*'",
            -1, &tables, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot inspect per-account concept tables: %s", sqlite3_errmsg(db));
        return -1;
    }
    while ((rc = sqlite3_step(tables)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(tables, 0);
        if (!name) continue;
        int changed = update_concept_table(db, (const char *)name, concept_id, error, error_size);
        if (changed < 0) {
            sqlite3_finalize(tables);
            return -1;
        }
        total += changed;
    }
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot read per-account concept tables: %s", sqlite3_errmsg(db));
        sqlite3_finalize(tables);
        return -1;
    }
    sqlite3_finalize(tables);
    return total;
}

static int update_app_db_references(sqlite3 *db, const char *concept_id, char *error, size_t error_size)
{
    int content_rows = update_contentinfo(db, error, error_size);
    if (content_rows <= 0) {
        if (content_rows == 0) snprintf(error, error_size, "PPSA01650 was not updated in tbl_contentinfo");
        return 0;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE tbl_conceptmetadata SET conceptName = ?, icon0Info = ? WHERE localConceptId = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare tbl_conceptmetadata update: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, concept_id, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update tbl_conceptmetadata: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }
    int concept_rows = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    int account_rows = update_per_account_tables(db, concept_id, error, error_size);
    if (account_rows < 0) return 0;
    if (concept_rows + account_rows <= 0) {
        snprintf(error, error_size, "PPSA01650 has no concept metadata rows");
        return 0;
    }

    if (sqlite3_prepare_v2(db,
            "SELECT titleName, icon0Info, "
            "json_extract(AppInfoJson, '$.TITLE'), "
            "json_extract(AppInfoJson, '$.TITLE_01'), "
            "json_extract(AppInfoJson, '$.icon0Info') "
            "FROM tbl_contentinfo WHERE titleId = ? LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot verify app.db title and icon fields: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, TITLE_ID, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int verified = 0;
    if (rc == SQLITE_ROW) {
        const unsigned char *title = sqlite3_column_text(stmt, 0);
        const unsigned char *icon = sqlite3_column_text(stmt, 1);
        const unsigned char *json_title = sqlite3_column_text(stmt, 2);
        const unsigned char *json_title_01 = sqlite3_column_text(stmt, 3);
        const unsigned char *json_icon = sqlite3_column_text(stmt, 4);
        verified = title && icon && json_title && json_title_01 && json_icon &&
            strcmp((const char *)title, NEW_TITLE) == 0 &&
            strcmp((const char *)icon, ICON_URI) == 0 &&
            strcmp((const char *)json_title, NEW_TITLE) == 0 &&
            strcmp((const char *)json_title_01, NEW_TITLE) == 0 &&
            strcmp((const char *)json_icon, ICON_URI) == 0;
    }
    sqlite3_finalize(stmt);
    if (!verified) {
        snprintf(error, error_size, "app.db title or icon verification failed");
        return 0;
    }
    return 1;
}

static int update_appinfo_references(sqlite3 *db, const char *concept_id, char *error, size_t error_size)
{
    sqlite3_stmt *stmt = NULL;
    const char *title_sql =
        "UPDATE tbl_appinfo SET val = ? WHERE titleId = ? AND key IN ('TITLE', 'TITLE_01')";
    if (sqlite3_prepare_v2(db, title_sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "appinfo.db schema mismatch for title rows: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, TITLE_ID, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    int title_rows = sqlite3_changes(db);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update appinfo.db title rows: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    if (title_rows <= 0) {
        snprintf(error, error_size, "PPSA01650 title rows were not found in appinfo.db");
        return 0;
    }

    const char *concept_sql =
        "UPDATE tbl_conceptinfo SET val = ? WHERE local_concept_id = ? "
        "AND key IN ('concept_name', 'concept_name_01')";
    if (sqlite3_prepare_v2(db, concept_sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "appinfo.db schema mismatch for concept rows: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, NEW_TITLE, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, concept_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int concept_rows = sqlite3_changes(db);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update appinfo.db concept rows: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    if (concept_rows <= 0) {
        snprintf(error, error_size, "PPSA01650 concept rows were not found in appinfo.db");
        return 0;
    }
    return 1;
}

static int run_app_db_update(char *concept_id, size_t concept_id_size, char *error, size_t error_size)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(APP_DB_PATH, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot open app.db: %s", db ? sqlite3_errmsg(db) : "sqlite open failed");
        if (db) sqlite3_close(db);
        return 0;
    }
    sqlite3_busy_timeout(db, 5000);
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot begin app.db transaction: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    if (!find_local_concept_id(db, concept_id, concept_id_size, error, error_size)) goto app_rollback;
    if (!create_backup_if_missing(db, APP_DB_BACKUP, APP_DB_BACKUP_TEMP, "app.db", error, error_size))
        goto app_rollback;
    if (!update_app_db_references(db, concept_id, error, error_size)) goto app_rollback;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot commit app.db transaction: %s", sqlite3_errmsg(db));
        goto app_rollback;
    }
    sqlite3_close(db);
    return 1;

app_rollback:
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;
}

static int run_appinfo_db_update(const char *concept_id, char *error, size_t error_size)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(APPINFO_DB_PATH, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot open appinfo.db: %s", db ? sqlite3_errmsg(db) : "sqlite open failed");
        if (db) sqlite3_close(db);
        return 0;
    }
    sqlite3_busy_timeout(db, 5000);
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot begin appinfo.db transaction: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    if (!create_backup_if_missing(db, APPINFO_DB_BACKUP, APPINFO_DB_BACKUP_TEMP,
            "appinfo.db", error, error_size)) goto appinfo_rollback;
    if (!update_appinfo_references(db, concept_id, error, error_size)) goto appinfo_rollback;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot commit appinfo.db transaction: %s", sqlite3_errmsg(db));
        goto appinfo_rollback;
    }
    sqlite3_close(db);
    return 1;

appinfo_rollback:
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;
}



static int copy_file_if_missing(const char *source_path, const char *backup_path,
    const char *backup_temp, char *error, size_t error_size)
{
    if (access(backup_path, F_OK) == 0) return 1;
    (void)unlink(backup_temp);

    int source_fd = open(source_path, O_RDONLY);
    if (source_fd < 0) {
        snprintf(error, error_size, "cannot open %s: %s", source_path, strerror(errno));
        return 0;
    }
    int backup_fd = open(backup_temp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (backup_fd < 0) {
        snprintf(error, error_size, "cannot create backup for %s: %s", source_path, strerror(errno));
        close(source_fd);
        return 0;
    }

    unsigned char buffer[8192];
    int ok = 1;
    for (;;) {
        ssize_t amount = read(source_fd, buffer, sizeof(buffer));
        if (amount == 0) break;
        if (amount < 0) {
            if (errno == EINTR) continue;
            snprintf(error, error_size, "cannot read %s: %s", source_path, strerror(errno));
            ok = 0;
            break;
        }
        size_t written = 0;
        while (written < (size_t)amount) {
            ssize_t count = write(backup_fd, buffer + written, (size_t)amount - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) {
                snprintf(error, error_size, "cannot write backup for %s: %s", source_path, strerror(errno));
                ok = 0;
                break;
            }
            written += (size_t)count;
        }
        if (!ok) break;
    }
    if (ok && fsync(backup_fd) != 0) {
        snprintf(error, error_size, "cannot sync backup for %s: %s", source_path, strerror(errno));
        ok = 0;
    }
    if (close(source_fd) != 0 && ok) {
        snprintf(error, error_size, "cannot close %s: %s", source_path, strerror(errno));
        ok = 0;
    }
    if (close(backup_fd) != 0 && ok) {
        snprintf(error, error_size, "cannot close backup for %s: %s", source_path, strerror(errno));
        ok = 0;
    }
    if (ok && rename(backup_temp, backup_path) != 0) {
        snprintf(error, error_size, "cannot install backup for %s: %s", source_path, strerror(errno));
        ok = 0;
    }
    if (!ok) (void)unlink(backup_temp);
    return ok;
}

static int append_json_bytes(unsigned char **output, size_t *used, size_t *capacity,
    const unsigned char *bytes, size_t amount)
{
    if (amount > SIZE_MAX - *used) return 0;
    size_t needed = *used + amount;
    if (needed > *capacity) {
        size_t next = *capacity ? *capacity : 256;
        while (next < needed) {
            if (next > SIZE_MAX / 2) { next = needed; break; }
            next *= 2;
        }
        unsigned char *grown = realloc(*output, next);
        if (!grown) return 0;
        *output = grown;
        *capacity = next;
    }
    if (amount) memcpy(*output + *used, bytes, amount);
    *used = needed;
    return 1;
}

static int is_json_space(unsigned char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static int replace_param_title_names(const unsigned char *input, size_t input_size,
    unsigned char **output, size_t *output_size, int *replacement_count)
{
    static const unsigned char key[] = "titleName";
    static const unsigned char replacement[] = "\"SKYBOZ LOADER\"";
    unsigned char *result = NULL;
    size_t result_size = 0, capacity = 0, copy_from = 0, position = 0;
    int replacements = 0;

    while (position < input_size) {
        if (input[position] != '"') {
            position++;
            continue;
        }

        size_t string_end = position + 1;
        while (string_end < input_size) {
            if (input[string_end] == '\\') {
                if (string_end + 1 >= input_size) {
                    free(result);
                    return 0;
                }
                string_end += 2;
            } else if (input[string_end] == '"') {
                break;
            } else {
                string_end++;
            }
        }
        if (string_end >= input_size) {
            free(result);
            return 0;
        }

        size_t token_size = string_end - position - 1;
        int is_title_key = token_size == sizeof(key) - 1 &&
            memcmp(input + position + 1, key, sizeof(key) - 1) == 0;
        size_t colon = string_end + 1;
        while (colon < input_size && is_json_space(input[colon])) colon++;
        if (is_title_key && colon < input_size && input[colon] == ':') {
            size_t value = colon + 1;
            while (value < input_size && is_json_space(input[value])) value++;
            if (value < input_size && input[value] == '"') {
                size_t value_end = value + 1;
                while (value_end < input_size) {
                    if (input[value_end] == '\\') {
                        if (value_end + 1 >= input_size) {
                            free(result);
                            return 0;
                        }
                        value_end += 2;
                    } else if (input[value_end] == '"') {
                        break;
                    } else {
                        value_end++;
                    }
                }
                if (value_end >= input_size ||
                    !append_json_bytes(&result, &result_size, &capacity,
                        input + copy_from, value - copy_from) ||
                    !append_json_bytes(&result, &result_size, &capacity,
                        replacement, sizeof(replacement) - 1)) {
                    free(result);
                    return 0;
                }
                replacements++;
                copy_from = value_end + 1;
                position = copy_from;
                continue;
            }
        }
        position = string_end + 1;
    }

    if (!append_json_bytes(&result, &result_size, &capacity,
            input + copy_from, input_size - copy_from)) {
        free(result);
        return 0;
    }
    *output = result;
    *output_size = result_size;
    *replacement_count = replacements;
    return 1;
}

static int update_param_json_file(const char *path, const char *backup_path,
    const char *backup_temp, char *error, size_t error_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(error, error_size, "cannot open %s: %s", path, strerror(errno));
        return 0;
    }
    struct stat info;
    if (fstat(fd, &info) != 0 || info.st_size <= 0 || info.st_size > 16 * 1024 * 1024) {
        snprintf(error, error_size, "invalid or oversized param.json at %s", path);
        close(fd);
        return 0;
    }

    size_t input_size = (size_t)info.st_size;
    unsigned char *input = malloc(input_size + 1);
    if (!input) {
        snprintf(error, error_size, "out of memory reading %s", path);
        close(fd);
        return 0;
    }
    size_t read_total = 0;
    while (read_total < input_size) {
        ssize_t amount = read(fd, input + read_total, input_size - read_total);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            snprintf(error, error_size, "short read from %s", path);
            free(input);
            close(fd);
            return 0;
        }
        read_total += (size_t)amount;
    }
    close(fd);

    if (!copy_file_if_missing(path, backup_path, backup_temp, error, error_size)) {
        free(input);
        return 0;
    }

    unsigned char *patched = NULL;
    size_t patched_size = 0;
    int replacements = 0;
    if (!replace_param_title_names(input, input_size, &patched, &patched_size, &replacements) ||
        replacements <= 0) {
        snprintf(error, error_size, "%s has no valid localized titleName fields", path);
        free(input);
        free(patched);
        return 0;
    }

    char temp_path[1024];
    if (snprintf(temp_path, sizeof(temp_path), "%s.skyboz-tmp", path) >= (int)sizeof(temp_path)) {
        snprintf(error, error_size, "param.json path is too long");
        free(input);
        free(patched);
        return 0;
    }
    (void)unlink(temp_path);
    int output_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (output_fd < 0) {
        snprintf(error, error_size, "cannot create temporary param.json for %s: %s", path, strerror(errno));
        free(input);
        free(patched);
        return 0;
    }

    size_t written = 0;
    int ok = 1;
    while (written < patched_size) {
        ssize_t amount = write(output_fd, patched + written, patched_size - written);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            snprintf(error, error_size, "cannot write temporary param.json for %s: %s", path, strerror(errno));
            ok = 0;
            break;
        }
        written += (size_t)amount;
    }
    if (ok && fchmod(output_fd, info.st_mode & 0777) != 0) {
        snprintf(error, error_size, "cannot preserve %s permissions: %s", path, strerror(errno));
        ok = 0;
    }
    if (ok && fsync(output_fd) != 0) {
        snprintf(error, error_size, "cannot sync temporary param.json for %s: %s", path, strerror(errno));
        ok = 0;
    }
    if (close(output_fd) != 0 && ok) {
        snprintf(error, error_size, "cannot close temporary param.json for %s: %s", path, strerror(errno));
        ok = 0;
    }
    if (ok && rename(temp_path, path) != 0) {
        snprintf(error, error_size, "cannot install updated param.json at %s: %s", path, strerror(errno));
        ok = 0;
    }
    if (!ok) (void)unlink(temp_path);

    if (ok) {
        int verify_fd = open(path, O_RDONLY);
        unsigned char *verify = verify_fd >= 0 ? malloc(patched_size ? patched_size : 1) : NULL;
        if (verify_fd < 0 || !verify) {
            snprintf(error, error_size, "cannot verify updated param.json at %s", path);
            ok = 0;
        } else {
            size_t verified = 0;
            while (verified < patched_size) {
                ssize_t amount = read(verify_fd, verify + verified, patched_size - verified);
                if (amount < 0 && errno == EINTR) continue;
                if (amount <= 0) break;
                verified += (size_t)amount;
            }
            if (verified != patched_size || memcmp(verify, patched, patched_size) != 0) {
                snprintf(error, error_size, "updated param.json verification failed at %s", path);
                ok = 0;
            }
        }
        if (verify_fd >= 0) close(verify_fd);
        free(verify);
    }

    free(input);
    free(patched);
    return ok;
}

int main(void)
{
    (void)mkdir(BACKUP_DIR, 0777);
    write_status("RUNNING: helper started; checking SKYBOZ icon");
    if (access(ICON_PATH, R_OK) != 0) {
        write_status("ERROR: persistent SKYBOZ icon file is missing");
        return 1;
    }

    char error[512] = {0};
    char concept_id[128] = {0};
    int system_param_updated = 0;
    if (access(SYSTEM_PARAM_PATH, F_OK) == 0) {
        write_status("RUNNING: updating system param.json");
        if (!update_param_json_file(SYSTEM_PARAM_PATH, SYSTEM_PARAM_BACKUP,
                SYSTEM_PARAM_BACKUP_TEMP, error, sizeof(error))) {
            char message[600];
            snprintf(message, sizeof(message), "ERROR: system param.json update failed: %s", error);
            write_status(message);
            return 1;
        }
        system_param_updated = 1;
    } else if (errno != ENOENT) {
        char message[600];
        snprintf(message, sizeof(message), "ERROR: cannot check system param.json: %s", strerror(errno));
        write_status(message);
        return 1;
    }
    write_status("RUNNING: updating user param.json");
    if (!update_param_json_file(USER_PARAM_PATH, USER_PARAM_BACKUP,
            USER_PARAM_BACKUP_TEMP, error, sizeof(error))) {
        char message[600];
        snprintf(message, sizeof(message), "ERROR: user param.json update failed: %s", error);
        write_status(message);
        return 1;
    }
    write_status("RUNNING: backing up and updating app.db");
    if (!run_app_db_update(concept_id, sizeof(concept_id), error, sizeof(error))) {
        char message[600];
        snprintf(message, sizeof(message), "ERROR: %s", error[0] ? error : "app.db update failed");
        write_status(message);
        return 1;
    }
    write_status("RUNNING: backing up and updating appinfo.db");
    if (!run_appinfo_db_update(concept_id, error, sizeof(error))) {
        char message[600];
        snprintf(message, sizeof(message), "ERROR: %s", error[0] ? error : "appinfo.db update failed");
        write_status(message);
        return 1;
    }

    if (system_param_updated) {
        write_status("OK: SKYBOZ LOADER saved in system/user param.json and app databases; icon metadata is persistent");
    } else {
        write_status("OK: SKYBOZ LOADER saved in user param.json and app databases; system param.json was not present");
    }
    return 0;
}
