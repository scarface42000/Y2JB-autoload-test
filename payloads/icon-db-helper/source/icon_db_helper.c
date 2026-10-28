#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define APP_DB_PATH "/system_data/priv/mms/app.db"
#define BACKUP_DIR "/data/skyboz-loader"
#define BACKUP_PATH BACKUP_DIR "/app.db.before-icon"
#define BACKUP_TEMP BACKUP_PATH ".tmp"
#define STATUS_PATH BACKUP_DIR "/icon-db.status"
#define STATUS_TEMP STATUS_PATH ".tmp"
#define ICON_PATH "/user/appmeta/PPSA01650/SKYBOZ_LOADER_icon0.png"
#define ICON_URI ICON_PATH "?ts=1"
#define TITLE_ID "PPSA01650"

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

static int create_backup_if_missing(sqlite3 *source, char *error, size_t error_size)
{
    if (mkdir(BACKUP_DIR, 0777) != 0 && errno != EEXIST) {
        snprintf(error, error_size, "cannot create backup folder: %s", strerror(errno));
        return 0;
    }

    if (access(BACKUP_PATH, F_OK) == 0) {
        if (database_integrity_ok(BACKUP_PATH)) return 1;
        snprintf(error, error_size, "existing app.db backup failed integrity check; refusing to overwrite it");
        return 0;
    }

    (void)unlink(BACKUP_TEMP);
    sqlite3 *destination = NULL;
    int rc = sqlite3_open_v2(BACKUP_TEMP, &destination,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot create app.db backup: %s",
            destination ? sqlite3_errmsg(destination) : "sqlite open failed");
        if (destination) sqlite3_close(destination);
        (void)unlink(BACKUP_TEMP);
        return 0;
    }

    sqlite3_busy_timeout(destination, 5000);
    sqlite3_backup *backup = sqlite3_backup_init(destination, "main", source, "main");
    if (!backup) {
        snprintf(error, error_size, "cannot start SQLite backup: %s", sqlite3_errmsg(destination));
        sqlite3_close(destination);
        (void)unlink(BACKUP_TEMP);
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
        !database_integrity_ok(BACKUP_TEMP)) {
        snprintf(error, error_size, "SQLite backup did not pass integrity check");
        (void)unlink(BACKUP_TEMP);
        return 0;
    }

    if (rename(BACKUP_TEMP, BACKUP_PATH) != 0) {
        snprintf(error, error_size, "cannot install app.db backup: %s", strerror(errno));
        (void)unlink(BACKUP_TEMP);
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
        "UPDATE tbl_contentinfo SET icon0Info = ?, "
        "AppInfoJson = json_set(AppInfoJson, '$.icon0Info', ?) "
        "WHERE titleId = ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare tbl_contentinfo update: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, TITLE_ID, -1, SQLITE_STATIC);
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

static int update_table_by_concept(sqlite3 *db, const char *table, const char *concept_id,
    char *error, size_t error_size)
{
    char *sql = sqlite3_mprintf("UPDATE \"%w\" SET icon0Info = ? WHERE localConceptId = ?", table);
    if (!sql) {
        snprintf(error, error_size, "out of memory while preparing account metadata update");
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare %s update: %s", table, sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, concept_id, -1, SQLITE_STATIC);
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

static int update_concept_tables(sqlite3 *db, const char *concept_id, char *error, size_t error_size)
{
    sqlite3_stmt *tables = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'tbl_concepticoninfo_*'",
            -1, &tables, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot inspect per-account icon tables: %s", sqlite3_errmsg(db));
        return -1;
    }

    int total = 0;
    int rc;
    while ((rc = sqlite3_step(tables)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(tables, 0);
        if (!name) continue;
        int changed = update_table_by_concept(db, (const char *)name, concept_id, error, error_size);
        if (changed < 0) {
            sqlite3_finalize(tables);
            return -1;
        }
        total += changed;
    }
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot read per-account icon tables: %s", sqlite3_errmsg(db));
        sqlite3_finalize(tables);
        return -1;
    }
    sqlite3_finalize(tables);
    return total;
}

static int update_all_icon_references(sqlite3 *db, const char *concept_id, char *error, size_t error_size)
{
    int content_rows = update_contentinfo(db, error, error_size);
    if (content_rows <= 0) {
        if (content_rows == 0) snprintf(error, error_size, "PPSA01650 was not updated in tbl_contentinfo");
        return 0;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE tbl_conceptmetadata SET icon0Info = ? WHERE localConceptId = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot prepare tbl_conceptmetadata update: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, ICON_URI, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, concept_id, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        snprintf(error, error_size, "cannot update tbl_conceptmetadata: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }
    int concept_rows = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    int account_rows = update_concept_tables(db, concept_id, error, error_size);
    if (account_rows < 0) return 0;
    if (concept_rows + account_rows <= 0) {
        snprintf(error, error_size, "PPSA01650 has no concept icon metadata rows");
        return 0;
    }

    if (sqlite3_prepare_v2(db,
            "SELECT icon0Info, json_extract(AppInfoJson, '$.icon0Info') "
            "FROM tbl_contentinfo WHERE titleId = ? LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(error, error_size, "cannot verify app.db icon path: %s", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(stmt, 1, TITLE_ID, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int verified = 0;
    if (rc == SQLITE_ROW) {
        const unsigned char *column_path = sqlite3_column_text(stmt, 0);
        const unsigned char *json_path = sqlite3_column_text(stmt, 1);
        verified = column_path && json_path &&
            strcmp((const char *)column_path, ICON_URI) == 0 &&
            strcmp((const char *)json_path, ICON_URI) == 0;
    }
    sqlite3_finalize(stmt);
    if (!verified) {
        snprintf(error, error_size, "app.db icon path verification failed");
        return 0;
    }
    return 1;
}

int main(void)
{
    (void)mkdir(BACKUP_DIR, 0777);
    if (access(ICON_PATH, R_OK) != 0) {
        write_status("ERROR: persistent SKYBOZ icon file is missing");
        return 1;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(APP_DB_PATH, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        char message[512];
        snprintf(message, sizeof(message), "ERROR: cannot open app.db: %s",
            db ? sqlite3_errmsg(db) : "sqlite open failed");
        write_status(message);
        if (db) sqlite3_close(db);
        return 1;
    }
    sqlite3_busy_timeout(db, 5000);

    char error[512] = {0};
    char concept_id[128] = {0};
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, sizeof(error), "cannot begin app.db transaction: %s", sqlite3_errmsg(db));
        goto fail;
    }
    if (!find_local_concept_id(db, concept_id, sizeof(concept_id), error, sizeof(error))) goto rollback;
    if (!create_backup_if_missing(db, error, sizeof(error))) goto rollback;
    if (!update_all_icon_references(db, concept_id, error, sizeof(error))) goto rollback;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(error, sizeof(error), "cannot commit app.db transaction: %s", sqlite3_errmsg(db));
        goto rollback;
    }

    sqlite3_close(db);
    sync();
    write_status("OK: SKYBOZ tile metadata saved; restart the console once to refresh its cached tile");
    return 0;

rollback:
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
fail:
    {
        char message[600];
        snprintf(message, sizeof(message), "ERROR: %s", error[0] ? error : sqlite3_errmsg(db));
        sqlite3_close(db);
        write_status(message);
        return 1;
    }
}
