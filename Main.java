import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class Main {

    private static final String VAULT_FILE = "vault.dat";
    private static final byte[] MAGIC = "PMV1".getBytes(StandardCharsets.US_ASCII);
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int KEY_LENGTH_BITS = 256;

    private final Console console;
    private final Map<String, Entry> entries = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private byte[] salt;
    private SecretKey masterKey;
    private boolean dirty = false;

    public static void main(String[] args) {
        Main app = new Main();
        app.run();
    }

    private Main() {
        this.console = new Console();
    }

    // Main loop

    private void run() {
        console.println("==============================================");
        console.println("           Password Manager");
        console.println("==============================================");

        try {
            if (Files.exists(Paths.get(VAULT_FILE))) {
                unlockExistingVault();
            } else {
                createNewVault();
            }
        } catch (Exception e) {
            console.println("Fatal error: " + e.getMessage());
            return;
        }

        boolean running = true;
        while (running) {
            printMenu();
            String choice = console.readLine("Choose an option: ").trim();
            try {
                switch (choice) {
                    case "1": addEntry(); break;
                    case "2": viewEntry(); break;
                    case "3": listEntries(); break;
                    case "4": updateEntry(); break;
                    case "5": deleteEntry(); break;
                    case "6": generatePassword(); break;
                    case "7": changeMasterPassword(); break;
                    case "8": saveVault(); console.println("Vault saved."); break;
                    case "9": running = false; break;
                    default: console.println("Unknown option, try again.");
                }
            } catch (Exception e) {
                console.println("Error: " + e.getMessage());
            }
        }

        if (dirty) {
            String ans = console.readLine("You have unsaved changes. Save before exit? (y/n): ").trim();
            if (ans.equalsIgnoreCase("y")) {
                try {
                    saveVault();
                    console.println("Vault saved.");
                } catch (Exception e) {
                    console.println("Failed to save: " + e.getMessage());
                }
            }
        }
        console.println("Goodbye.");
    }

    private void printMenu() {
        console.println("");
        console.println("---------------- MENU ----------------");
        console.println("1) Add new entry");
        console.println("2) View / reveal a password");
        console.println("3) List all entries (services only)");
        console.println("4) Update an entry");
        console.println("5) Delete an entry");
        console.println("6) Generate a strong random password");
        console.println("7) Change master password");
        console.println("8) Save vault");
        console.println("9) Exit");
        console.println("---------------------------------------");
    }

    // Vault creation / unlocking

    private void createNewVault() throws Exception {
        console.println("No vault found. Let's create one.");
        char[] pw1, pw2;
        while (true) {
            pw1 = console.readPassword("Create a master password: ");
            if (pw1.length < 8) {
                console.println("Master password should be at least 8 characters. Try again.");
                continue;
            }
            pw2 = console.readPassword("Confirm master password: ");
            if (Arrays.equals(pw1, pw2)) {
                Arrays.fill(pw2, '\0');
                break;
            }
            console.println("Passwords did not match. Try again.");
        }
        this.salt = randomBytes(SALT_LEN);
        this.masterKey = deriveKey(pw1, salt);
        Arrays.fill(pw1, '\0');
        dirty = true;
        saveVault();
        console.println("Vault created and unlocked.");
    }

    private void unlockExistingVault() throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get(VAULT_FILE));
        if (fileBytes.length < MAGIC.length + SALT_LEN + IV_LEN) {
            throw new IOException("Vault file is corrupt or too small.");
        }
        int offset = 0;
        byte[] magic = Arrays.copyOfRange(fileBytes, offset, offset + MAGIC.length);
        offset += MAGIC.length;
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Not a valid vault file.");
        }
        this.salt = Arrays.copyOfRange(fileBytes, offset, offset + SALT_LEN);
        offset += SALT_LEN;
        byte[] iv = Arrays.copyOfRange(fileBytes, offset, offset + IV_LEN);
        offset += IV_LEN;
        byte[] cipherText = Arrays.copyOfRange(fileBytes, offset, fileBytes.length);

        int attempts = 0;
        while (attempts < 5) {
            char[] pw = console.readPassword("Enter master password to unlock vault: ");
            SecretKey key = deriveKey(pw, salt);
            Arrays.fill(pw, '\0');
            try {
                byte[] plain = decrypt(key, iv, cipherText);
                loadEntriesFromBytes(plain);
                this.masterKey = key;
                console.println("Vault unlocked. " + entries.size() + " entr" +
                        (entries.size() == 1 ? "y" : "ies") + " loaded.");
                return;
            } catch (AEADBadTagException e) {
                attempts++;
                console.println("Incorrect password. Attempts remaining: " + (5 - attempts));
            }
        }
        throw new SecurityException("Too many failed attempts. Exiting.");
    }

    private void changeMasterPassword() throws Exception {
        char[] pw1, pw2;
        while (true) {
            pw1 = console.readPassword("New master password: ");
            if (pw1.length < 8) {
                console.println("Master password should be at least 8 characters. Try again.");
                continue;
            }
            pw2 = console.readPassword("Confirm new master password: ");
            if (Arrays.equals(pw1, pw2)) {
                Arrays.fill(pw2, '\0');
                break;
            }
            console.println("Passwords did not match. Try again.");
        }
        this.salt = randomBytes(SALT_LEN);
        this.masterKey = deriveKey(pw1, salt);
        Arrays.fill(pw1, '\0');
        dirty = true;
        saveVault();
        console.println("Master password changed and vault re-encrypted.");
    }

    // Entry operations

    private void addEntry() {
        String service = console.readLine("Service/site name: ").trim();
        if (service.isEmpty()) {
            console.println("Service name cannot be empty.");
            return;
        }
        if (entries.containsKey(service)) {
            console.println("An entry for '" + service + "' already exists. Use update instead.");
            return;
        }
        String username = console.readLine("Username/email: ").trim();
        char[] pwChars = promptForPassword();
        if (pwChars == null) return;
        Entry e = new Entry(service, username, new String(pwChars));
        Arrays.fill(pwChars, '\0');
        entries.put(service, e);
        dirty = true;
        console.println("Entry added for '" + service + "'.");
    }

    private char[] promptForPassword() {
        String genChoice = console.readLine("Generate a random password for this entry? (y/n): ").trim();
        if (genChoice.equalsIgnoreCase("y")) {
            int length = readIntWithDefault("Length (default 16): ", 16);
            String generated = generateRandomPassword(length);
            console.println("Generated password: " + generated);
            return generated.toCharArray();
        } else {
            return console.readPassword("Password: ");
        }
    }

    private void viewEntry() {
        String service = console.readLine("Service name to view: ").trim();
        Entry e = entries.get(service);
        if (e == null) {
            console.println("No entry found for '" + service + "'.");
            return;
        }
        console.println("Service : " + e.service);
        console.println("Username: " + e.username);
        console.println("Password: " + e.password);
    }

    private void listEntries() {
        if (entries.isEmpty()) {
            console.println("Vault is empty.");
            return;
        }
        console.println("Stored services (" + entries.size() + "):");
        int i = 1;
        for (Entry e : entries.values()) {
            console.println("  " + (i++) + ". " + e.service + "  (user: " + e.username + ")");
        }
    }

    private void updateEntry() {
        String service = console.readLine("Service name to update: ").trim();
        Entry e = entries.get(service);
        if (e == null) {
            console.println("No entry found for '" + service + "'.");
            return;
        }
        String newUser = console.readLine("New username (blank to keep '" + e.username + "'): ").trim();
        if (!newUser.isEmpty()) e.username = newUser;

        String changePw = console.readLine("Change password? (y/n): ").trim();
        if (changePw.equalsIgnoreCase("y")) {
            char[] pwChars = promptForPassword();
            if (pwChars != null) {
                e.password = new String(pwChars);
                Arrays.fill(pwChars, '\0');
            }
        }
        dirty = true;
        console.println("Entry for '" + service + "' updated.");
    }

    private void deleteEntry() {
        String service = console.readLine("Service name to delete: ").trim();
        if (entries.remove(service) != null) {
            dirty = true;
            console.println("Entry for '" + service + "' deleted.");
        } else {
            console.println("No entry found for '" + service + "'.");
        }
    }

    private void generatePassword() {
        int length = readIntWithDefault("Password length (default 16): ", 16);
        String pw = generateRandomPassword(length);
        console.println("Generated password: " + pw);
    }

    private int readIntWithDefault(String prompt, int def) {
        String s = console.readLine(prompt).trim();
        if (s.isEmpty()) return def;
        try {
            int v = Integer.parseInt(s);
            return v > 0 ? v : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    // Persistence (serialize entries -> encrypt -> write file)

    private void saveVault() throws Exception {
        byte[] plain = entriesToBytes();
        byte[] iv = randomBytes(IV_LEN);
        byte[] cipherText = encrypt(masterKey, iv, plain);

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            bos.write(MAGIC);
            bos.write(salt);
            bos.write(iv);
            bos.write(cipherText);
            Files.write(Paths.get(VAULT_FILE), bos.toByteArray());
        }
        dirty = false;
    }

    private byte[] entriesToBytes() {
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries.values()) {
            sb.append(escape(e.service)).append('\u0001')
              .append(escape(e.username)).append('\u0001')
              .append(escape(e.password)).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void loadEntriesFromBytes(byte[] plain) {
        entries.clear();
        String data = new String(plain, StandardCharsets.UTF_8);
        if (data.isEmpty()) return;
        for (String line : data.split("\n", -1)) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\u0001", -1);
            if (parts.length != 3) continue;
            Entry e = new Entry(unescape(parts[0]), unescape(parts[1]), unescape(parts[2]));
            entries.put(e.service, e);
        }
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\u0001", "\\u1");
    }

    private String unescape(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                if (next == 'n') { out.append('\n'); i++; continue; }
                if (next == '\\') { out.append('\\'); i++; continue; }
                if (next == 'u' && i + 2 < s.length() && s.charAt(i + 2) == '1') {
                    out.append('\u0001'); i += 2; continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }

    // Cryptography helpers

    private static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(SecretKey key, byte[] iv, byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(plaintext);
    }

    private static byte[] decrypt(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(cipherText);
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static final String PW_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String PW_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String PW_DIGITS = "0123456789";
    private static final String PW_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";
    private static final String PW_ALL = PW_LOWER + PW_UPPER + PW_DIGITS + PW_SYMBOLS;

    private static String generateRandomPassword(int length) {
        if (length < 4) length = 4;
        SecureRandom rnd = new SecureRandom();
        char[] result = new char[length];
        result[0] = PW_LOWER.charAt(rnd.nextInt(PW_LOWER.length()));
        result[1] = PW_UPPER.charAt(rnd.nextInt(PW_UPPER.length()));
        result[2] = PW_DIGITS.charAt(rnd.nextInt(PW_DIGITS.length()));
        result[3] = PW_SYMBOLS.charAt(rnd.nextInt(PW_SYMBOLS.length()));
        for (int i = 4; i < length; i++) {
            result[i] = PW_ALL.charAt(rnd.nextInt(PW_ALL.length()));
        }
        for (int i = result.length - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            char tmp = result[i];
            result[i] = result[j];
            result[j] = tmp;
        }
        return new String(result);
    }

    // Data model

    private static class Entry {
        String service;
        String username;
        String password;

        Entry(String service, String username, String password) {
            this.service = service;
            this.username = username;
            this.password = password;
        }
    }


    private static class Console {
        private final java.io.Console sysConsole = System.console();
        private final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        void println(String s) {
            System.out.println(s);
        }

        String readLine(String prompt) {
            System.out.print(prompt);
            System.out.flush();
            if (sysConsole != null) {
                return sysConsole.readLine();
            }
            try {
                String line = reader.readLine();
                return line == null ? "" : line;
            } catch (IOException e) {
                return "";
            }
        }

        char[] readPassword(String prompt) {
            if (sysConsole != null) {
                return sysConsole.readPassword(prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            try {
                String line = reader.readLine();
                return (line == null ? "" : line).toCharArray();
            } catch (IOException e) {
                return new char[0];
            }
        }
    }
}