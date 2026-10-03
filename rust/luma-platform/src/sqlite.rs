//! Narrow SQLite ABI adapter. SQL is fixed by callers; values are bound.
use crate::Result;
use std::ffi::{c_void, CString};
use std::ptr;

#[link(name = "libsqlite3.so.0", kind = "dylib", modifiers = "+verbatim")]
extern "C" {
    fn sqlite3_open_v2(name: *const i8, db: *mut *mut c_void, flags: i32, vfs: *const i8) -> i32;
    fn sqlite3_close_v2(db: *mut c_void) -> i32;
    fn sqlite3_busy_timeout(db: *mut c_void, ms: i32) -> i32;
    fn sqlite3_limit(db: *mut c_void, category: i32, value: i32) -> i32;
    fn sqlite3_prepare_v2(
        db: *mut c_void,
        sql: *const i8,
        n: i32,
        stmt: *mut *mut c_void,
        tail: *mut *const i8,
    ) -> i32;
    fn sqlite3_bind_text(
        stmt: *mut c_void,
        index: i32,
        value: *const i8,
        bytes: i32,
        destructor: *const c_void,
    ) -> i32;
    fn sqlite3_step(stmt: *mut c_void) -> i32;
    fn sqlite3_finalize(stmt: *mut c_void) -> i32;
    fn sqlite3_column_count(stmt: *mut c_void) -> i32;
    fn sqlite3_column_text(stmt: *mut c_void, column: i32) -> *const u8;
    fn sqlite3_column_bytes(stmt: *mut c_void, column: i32) -> i32;
    fn sqlite3_exec(
        db: *mut c_void,
        sql: *const i8,
        callback: *const c_void,
        context: *mut c_void,
        error: *mut *mut i8,
    ) -> i32;
}

pub(crate) struct Connection(*mut c_void);
impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            sqlite3_close_v2(self.0);
        }
    }
}
struct Statement(*mut c_void);
impl Drop for Statement {
    fn drop(&mut self) {
        unsafe {
            sqlite3_finalize(self.0);
        }
    }
}

fn check(code: i32) -> Result<()> {
    if code != 0 {
        return Err(format!("native SQLite operation refused ({code})").into());
    }
    Ok(())
}

impl Connection {
    pub(crate) fn open(path: &std::path::Path) -> Result<Self> {
        let name = CString::new(path.to_str().ok_or("non-UTF8 SQLite path")?)?;
        let mut db = ptr::null_mut();
        // READWRITE, FULLMUTEX, PRIVATECACHE, NOFOLLOW. No runtime CREATE or URI.
        let code = unsafe {
            sqlite3_open_v2(
                name.as_ptr(),
                &mut db,
                0x2 | 0x10000 | 0x40000 | 0x1000000,
                ptr::null(),
            )
        };
        if db.is_null() {
            return Err("native SQLite allocation failed".into());
        }
        let connection = Self(db);
        check(code)?;
        check(unsafe { sqlite3_busy_timeout(db, 250) })?;
        unsafe {
            sqlite3_limit(db, 0, 65536); // Value/row length.
            sqlite3_limit(db, 1, 65536); // SQL length.
            sqlite3_limit(db, 2, 32); // Columns.
            sqlite3_limit(db, 7, 0); // Attached databases.
        }
        connection.exec("PRAGMA trusted_schema=OFF;")?;
        connection.exec("PRAGMA foreign_keys=ON;")?;
        connection.exec("PRAGMA synchronous=FULL;")?;
        connection.exec("PRAGMA temp_store=MEMORY;")?;
        connection.exec("PRAGMA cell_size_check=ON;")?;
        connection.exec("PRAGMA wal_autocheckpoint=256;")?;
        if connection.query("PRAGMA synchronous", &[], 1)? != [vec!["2".to_owned()]]
            || connection.query("PRAGMA foreign_keys", &[], 1)? != [vec!["1".to_owned()]]
        {
            return Err("native SQLite durability configuration unavailable".into());
        }
        Ok(connection)
    }

    // Only fixed internal schema/transaction/PRAGMA statements call this.
    pub(crate) fn exec(&self, sql: &str) -> Result<()> {
        let sql = CString::new(sql)?;
        check(unsafe {
            sqlite3_exec(
                self.0,
                sql.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })
    }

    pub(crate) fn query(
        &self,
        sql: &str,
        values: &[&str],
        maximum: usize,
    ) -> Result<Vec<Vec<String>>> {
        let sql = CString::new(sql)?;
        let mut stmt = ptr::null_mut();
        let mut tail = ptr::null();
        let code = unsafe { sqlite3_prepare_v2(self.0, sql.as_ptr(), -1, &mut stmt, &mut tail) };
        let statement = Statement(stmt);
        check(code)?;
        if stmt.is_null() || tail.is_null() || unsafe { *tail } != 0 {
            return Err("native SQLite requires one complete statement".into());
        }
        for (index, value) in values.iter().enumerate() {
            if value.len() > 16384 {
                return Err("oversized SQLite bound value".into());
            }
            // SQLITE_TRANSIENT: SQLite copies bytes before this call returns.
            check(unsafe {
                sqlite3_bind_text(
                    stmt,
                    index as i32 + 1,
                    value.as_ptr().cast(),
                    value.len() as i32,
                    (-1isize) as *const c_void,
                )
            })?;
        }
        let columns = unsafe { sqlite3_column_count(stmt) };
        if !(0..=32).contains(&columns) {
            return Err("invalid SQLite column count".into());
        }
        let mut rows = Vec::new();
        loop {
            match unsafe { sqlite3_step(stmt) } {
                101 => break,
                100 => {
                    if rows.len() >= maximum {
                        return Err("native SQLite row bound exceeded".into());
                    }
                    let mut row = Vec::new();
                    for column in 0..columns {
                        let value = unsafe { sqlite3_column_text(stmt, column) };
                        let bytes = unsafe { sqlite3_column_bytes(stmt, column) };
                        if value.is_null() || !(0..=16384).contains(&bytes) {
                            return Err("invalid SQLite result value".into());
                        }
                        row.push(
                            std::str::from_utf8(unsafe {
                                std::slice::from_raw_parts(value, bytes as usize)
                            })?
                            .to_owned(),
                        );
                    }
                    rows.push(row);
                }
                error => {
                    check(error)?;
                    return Err("unexpected SQLite state".into());
                }
            }
        }
        drop(statement);
        Ok(rows)
    }
}
