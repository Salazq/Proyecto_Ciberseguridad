package org.example.proyecto_ciber;

import javafx.application.Application;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextInputDialog;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignApplication extends Application {

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Firmador y Verificador de Firmas");

        Button btnGenerarClaves = new Button("Generar par de claves RSA");
        Button btnFirmarArchivo = new Button("Firmar archivo");
        Button btnVerificarFirma = new Button("Verificar firma");

        btnGenerarClaves.setOnAction(e -> generarClaves());
        btnFirmarArchivo.setOnAction(e -> firmarArchivo());
        btnVerificarFirma.setOnAction(e -> verificarFirma());

        VBox buttonBox = new VBox(10);
        buttonBox.setPadding(new Insets(20));
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.getChildren().addAll(btnGenerarClaves, btnFirmarArchivo, btnVerificarFirma);

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(20));
        layout.getChildren().add(buttonBox);

        Scene scene = new Scene(layout, 400, 200);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * Genera un par de claves RSA y las guarda en archivos.
     */
    private void generarClaves() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Generar Claves");
        dialog.setHeaderText("Ingrese una contraseña para proteger la clave privada:");
        dialog.showAndWait().ifPresent(passphrase -> {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();

                Files.write(new File("keys/publicKey.key").toPath(), pair.getPublic().getEncoded());

                byte[] encryptedPrivateKey = encriptarDesencriptarClave(passphrase.toCharArray(), pair.getPrivate().getEncoded(), Cipher.ENCRYPT_MODE);

                Files.write(new File("keys/privateKey.key").toPath(), encryptedPrivateKey);

                showAlert("Éxito", "Claves generadas correctamente.");

            } catch (Exception e) {
                showAlert("Error", "Error al generar claves");
            }
        });
    }

    /**
     * Encrypts or decrypts a private key using a passphrase.
     *
     * @param passphrase the passphrase used to derive the encryption key
     * @param privateKey the private key to be encrypted or decrypted
     * @param mode the cipher mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
     * @return the encrypted or decrypted private key
     * @throws Exception if an error occurs during the encryption or decryption process
     */
    private byte[] encriptarDesencriptarClave(char[] passphrase, byte[] privateKey, int mode) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase, new byte[8], 1000, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(keyFactory.generateSecret(pbeKeySpec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, secretKey, new IvParameterSpec(new byte[16]));

        return cipher.doFinal(privateKey);
    }

    /**
     * Firma un archivo seleccionado por el usuario.
     */
    private void firmarArchivo() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo a firmar");
        File archivo = fileChooser.showOpenDialog(null);

        if (archivo != null) {

            fileChooser.setTitle("Seleccione el archivo que contiene la clave privada");
            File archivoFirma = fileChooser.showOpenDialog(null);


            if (archivoFirma != null) {

                TextInputDialog dialog = new TextInputDialog();
                dialog.setTitle("Firmar Archivo");
                dialog.setHeaderText("Ingrese la contraseña de la clave privada:");
                dialog.showAndWait().ifPresent(passphrase -> {
                    try {
                        PrivateKey privateKey = leerClavePrivada(archivoFirma, passphrase.toCharArray());

                        Signature signature = Signature.getInstance("SHA256withRSA");
                        signature.initSign(privateKey);

                        byte[] data = Files.readAllBytes(archivo.toPath());
                        signature.update(data);

                        byte[] firma = signature.sign();
                        Files.write(new File("keys/archivo.firma").toPath(), firma);

                        showAlert("Éxito", "Archivo firmado correctamente.");
                    } catch (Exception e) {
                        showAlert("Error", "Contraseña incorrecta");
                    }
                });
            }
        }
    }

    /**
     * Verifica la firma de un archivo seleccionado por el usuario.
     */
    private void verificarFirma() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo original");

        File archivoOriginal = fileChooser.showOpenDialog(null);

        if (archivoOriginal != null) {

            fileChooser.setTitle("Seleccione el archivo que contiene la clave pública");
            File archivoClave = fileChooser.showOpenDialog(null);

            if (archivoClave != null) {

                fileChooser.setTitle("Seleccione el archivo que contiene la firma");
                File archivoFirma = fileChooser.showOpenDialog(null);

                if (archivoFirma != null) {

                try {
                    PublicKey publicKey = leerClavePublica(archivoClave);

                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(publicKey);

                    byte[] data = Files.readAllBytes(archivoOriginal.toPath());
                    signature.update(data);

                    byte[] firma = Files.readAllBytes(archivoFirma.toPath());
                    boolean isValid = signature.verify(firma);

                    if (isValid){
                        showAlert("Resultado", "La firma es válida");
                    } else {
                        showAlert("Resultado", "La firma no es válida");
                    }
                } catch (Exception e) {
                    showAlert("Error", "Error al verificar firma");
                }
                }
            }
        }
    }

    /**
     * Lee una clave privada desde un archivo y la descifra usando una frase de contraseña.
     *
     * @param archivoClavePrivada el archivo que contiene la clave privada cifrada
     * @param passphrase la frase de contraseña para descifrar la clave privada
     * @return la clave privada descifrada
     * @throws Exception si ocurre un error durante la lectura o descifrado de la clave
     */
    private PrivateKey leerClavePrivada(File archivoClavePrivada, char [] passphrase) throws Exception {
        byte[] keyBytes = Files.readAllBytes(archivoClavePrivada.toPath());

        byte[] decryptedPrivateKey = encriptarDesencriptarClave(passphrase,keyBytes,Cipher.DECRYPT_MODE);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decryptedPrivateKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Lee una clave pública desde un archivo.
     *
     * @param archivoClavePublica el archivo que contiene la clave pública
     * @return la clave pública
     * @throws Exception si ocurre un error durante la lectura de la clave
     */
    private PublicKey leerClavePublica(File archivoClavePublica) throws Exception {
        byte[] keyBytes = Files.readAllBytes(archivoClavePublica.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Muestra una alerta con un título y un mensaje.
     *
     * @param title el título de la alerta
     * @param message el mensaje de la alerta
     */
    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}