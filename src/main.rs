//! src/main.rs

use dirs::data_dir;
use eframe::egui;
use rusqlite::{params, Connection};
use std::fs;

use rustamaner_lib::{decrypt, derive_key_from_password, encrypt, PasswordEntry};

fn main() {
    let options = eframe::NativeOptions::default();

    if let Err(e) = eframe::run_native(
        "Rustamaner",
        options,
        Box::new(|_cc| Ok(Box::<Rustamaner>::default())),
    ) {
        eprintln!("Failed to launch rustamaner: {}", e);
    }
}

struct Rustamaner {
    logged_in: bool,
    master_password: String,
    aes_key: Option<[u8; 32]>,
    service: String,
    username: String,
    password: String,
    conn: Connection,
    passwords: Vec<PasswordEntry>,
    show_passwords: Vec<bool>,
}

impl Default for Rustamaner {
    fn default() -> Self {
        let data_dir = data_dir().unwrap().join("rustamaner");
        if let Err(e) = fs::create_dir_all(&data_dir) {
            eprintln!("Failed to create data directory: {}", e);
            panic!("Failed to create data directory");
        }
        let db_path = data_dir.join("rustamaner.db");
        let conn = match Connection::open(&db_path) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to open database: {}", e);
                panic!("Failed to open database");
            }
        };
        if let Err(e) = conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )",
            [],
        ) {
            eprintln!("Failed to create table: {}", e);
            panic!("Failed to create table");
        }
        Self {
            logged_in: false,
            master_password: String::new(),
            aes_key: None,
            service: String::new(),
            username: String::new(),
            password: String::new(),
            conn,
            passwords: Vec::new(),
            show_passwords: Vec::new(),
        }
    }
}

impl Rustamaner {
    fn load_passwords(&mut self) -> Vec<PasswordEntry> {
        let mut stmt = match self
            .conn
            .prepare("SELECT id, service, username, password FROM passwords")
        {
            Ok(stmt) => stmt,
            Err(e) => {
                eprintln!("Failed to prepare statement: {}", e);
                panic!("Failed to prepare statement");
            }
        };
        let rows = match stmt.query_map([], |row| {
            Ok(PasswordEntry {
                id: row.get(0)?,
                service: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?,
            })
        }) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("Failed to query passwords: {}", e);
                panic!("Failed to query passwords");
            }
        };
        rows.map(|entry| match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Failed to get entry: {}", e);
                panic!("Failed to get entry");
            }
        })
        .collect()
    }

    fn add_entry_to_db(&mut self, entry: &PasswordEntry) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO passwords (service, username, password) VALUES (?1, ?2, ?3)",
            params![entry.service, entry.username, entry.password],
        ) {
            eprintln!("Failed to insert password entry: {}", e);
            panic!("Failed to insert password entry");
        }
    }

    fn delete_entry_from_db(&mut self, id: i64) {
        if let Err(e) = self
            .conn
            .execute("DELETE FROM passwords WHERE id = ?1", params![id])
        {
            eprintln!("Ошибка при удалении записи: {}", e);
            panic!("Failed to delete password entry");
        }
        if let Err(e) = self.conn.execute("VACUUM", []) {
            eprintln!("Ошибка при выполнении команды VACUUM: {}", e);
            panic!("Failed to execute VACUUM command");
        }
    }

    fn update_password_visibility(&mut self) {
        self.show_passwords = vec![false; self.passwords.len()];
    }

    fn decrypt_all_passwords(&mut self) {
        if let Some(_key) = self.aes_key {
            let decrypted_passwords: Vec<PasswordEntry> = self
                .load_passwords()
                .into_iter()
                .map(|entry| {
                    let decrypted_password = match decrypt(&self.master_password, &entry.password) {
                        Ok(password) => password,
                        Err(e) => {
                            eprintln!("Decryption failed: {}", e);
                            panic!("Decryption failed");
                        }
                    };
                    PasswordEntry {
                        id: entry.id,
                        service: entry.service,
                        username: entry.username,
                        password: decrypted_password,
                    }
                })
                .collect();
            self.passwords = decrypted_passwords;
            self.update_password_visibility();
        }
    }

    fn attempt_login(&mut self) {
        let key = derive_key_from_password(&self.master_password, &[0; 16]);
        self.aes_key = Some(key);
        self.logged_in = true;
        self.decrypt_all_passwords();
    }
}

impl eframe::App for Rustamaner {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ctx.set_visuals(egui::Visuals::dark());

            if !self.logged_in {
                ui.vertical_centered(|ui| {
                    ui.heading("Login");
                    let password_response = ui.add(
                        egui::TextEdit::singleline(&mut self.master_password)
                            .password(true)
                            .hint_text("Master Password"),
                    );
                    if password_response.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    {
                        self.attempt_login();
                    }
                });
            } else {
                egui::ScrollArea::both()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        ui.heading("New entry");

                        egui::Grid::new("password_entry_ui")
                            .num_columns(2)
                            .show(ui, |ui| {
                                ui.label("Service:");
                                ui.text_edit_singleline(&mut self.service);
                                ui.end_row();

                                ui.label("Username:");
                                ui.text_edit_singleline(&mut self.username);
                                ui.end_row();

                                ui.label("Password:");
                                ui.text_edit_singleline(&mut self.password);
                                ui.end_row();

                                if ui.button("Add Entry").clicked() {
                                    if let Some(_key) = self.aes_key {
                                        let encrypted_password =
                                            match encrypt(&self.master_password, &self.password) {
                                                Ok(password) => password,
                                                Err(e) => {
                                                    eprintln!("Encryption failed: {}", e);
                                                    panic!("Encryption failed");
                                                }
                                            };
                                        let entry = PasswordEntry {
                                            id: 0,
                                            service: self.service.clone(),
                                            username: self.username.clone(),
                                            password: encrypted_password,
                                        };
                                        self.add_entry_to_db(&entry);
                                        self.service.clear();
                                        self.username.clear();
                                        self.password.clear();
                                        self.decrypt_all_passwords();
                                    }
                                }
                            });

                        ui.separator();

                        ui.heading("Stored Passwords:");

                        egui::Grid::new("password_display_ui")
                            .num_columns(6)
                            .striped(true)
                            .show(ui, |ui| {
                                let passwords_clone = self.passwords.clone();
                                for (i, entry) in passwords_clone.iter().enumerate() {
                                    ui.label(format!("Service: {}", entry.service));

                                    ui.label(format!("Username: {}", entry.username));

                                    if self.show_passwords[i] {
                                        ui.label(format!("Password: {}", entry.password));
                                    } else {
                                        ui.label("Password: ********");
                                    }

                                    if ui.button("Show/Hide").clicked() {
                                        self.show_passwords[i] = !self.show_passwords[i];
                                    }

                                    if ui.button("Copy").clicked() {
                                        ui.output_mut(|o| o.copied_text = entry.password.clone());
                                    }

                                    if ui.button("Delete").clicked() {
                                        let id = entry.id;
                                        self.delete_entry_from_db(id.into());
                                        self.passwords = self.load_passwords();
                                        self.update_password_visibility();
                                    }

                                    ui.end_row();
                                }
                            });
                    });
            }
        });
    }
}
