# Rustamaner
Rustamaner is a password manager that locally stores your passwords in an encrypted .db file. Encryption is performed using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) and AEAD-algorithm [AES256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).

## Windows
To install this app on Windows, you need to download the rustamaner.exe file from the Releases page and run it from anywhere on your system.

## Linux
To install this application on Linux, you need to download the archive rustamaner-x86_64-linux.tar.gz from the Releases page. Inside the archive is the rustamaner executable file, which can be placed anywhere on your system. Preferably, the executable should be located in a directory included in your $PATH environment variable.

## Build
To build, you need cargo and a toolchain for your target platform. Just install Rust according to the Rust Book and you're all set.

```bash
git clone <this repository>

cd rustamaner

cargo install --path .
```

On Linux, it will place the executable in ~/.cargo/bin/

## Usage
When you open rustamaner, it will ask you to login with a master password. This master password is used as a salt to generate new passwords in your database.

The master password is never stored on the disc, only in RAM after you enter it when you log into the application. The master password is applied to the database only after you add an entry to it. If you log into the application for the first time and enter the password ‘qwerty’ but don't add any entries, the next time you start the application, it will allow you to use any password as well. Once you have added at least one entry to the database, it will not be possible to recover or use any other master password.

If you lose your master password, you will lose your data!
If you want to create a new one and permanently lose all data from the database, then delete the database file. It is most likely located at:
Windows: %APPDATA%/rustamaner
Linux: ~/.local/share/rustamaner