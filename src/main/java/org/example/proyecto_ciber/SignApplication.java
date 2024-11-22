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
import javafx.stage.DirectoryChooser;

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
    private File selectedDirectory;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Firmador y Verificador de Firmas");


        //Botones de la aplicación
        Button btnSeleccionarDirectorio = new Button("Seleccionar Directorio");
        Button btnGenerarClaves = new Button("Generar par de claves RSA");
        Button btnFirmarArchivo = new Button("Firmar archivo");
        Button btnVerificarFirma = new Button("Verificar firma");

        //lo botones están deshabilitados hasta que se seleccione un directorio
        btnGenerarClaves.setDisable(true);
        btnFirmarArchivo.setDisable(true);
        btnVerificarFirma.setDisable(true);

        //Evento de selección de directorio	
        btnSeleccionarDirectorio.setOnAction(e -> seleccionarDirectorio(primaryStage, btnGenerarClaves, btnFirmarArchivo, btnVerificarFirma));

        //Eventos de los botones
        btnGenerarClaves.setOnAction(e -> generarClaves());
        btnFirmarArchivo.setOnAction(e -> firmarArchivo());
        btnVerificarFirma.setOnAction(e -> verificarFirma());


        //Configuración de la pantalla y los estilos
        VBox buttonBox = new VBox(10);
        buttonBox.setPadding(new Insets(20));
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.getChildren().addAll(btnSeleccionarDirectorio, btnGenerarClaves, btnFirmarArchivo, btnVerificarFirma);

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(20));
        layout.getChildren().add(buttonBox);

        Scene scene = new Scene(layout, 400, 300);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void seleccionarDirectorio(Stage primaryStage, Button... buttons) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Seleccione el directorio");
        selectedDirectory = directoryChooser.showDialog(primaryStage);

        //Habilitar los botones si se selecciona un directorio
        if (selectedDirectory != null) {
            for (Button button : buttons) {
                button.setDisable(false);
            }
        }
    }

    /**
     * Genera un par de claves RSA y las guarda en archivos.
     */
    private void generarClaves() {

        if (selectedDirectory == null) {
            showAlert("Error", "Debe seleccionar un directorio primero.");
            return;
        }

        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Generar Claves");
        dialog.setHeaderText("Ingrese una contraseña para proteger la clave privada:");

        //Si se digitó una contraseña
        dialog.showAndWait().ifPresent(passphrase -> {

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();

                //Se guardan las clave pública
                Files.write(new File(selectedDirectory, "publicKey.key").toPath(), pair.getPublic().getEncoded());

                //Se encripta la clave privada
                byte[] encryptedPrivateKey = encriptarDesencriptarClave(passphrase.toCharArray(), pair.getPrivate().getEncoded(), Cipher.ENCRYPT_MODE);

                //Se guarda la clave privada encriptada
                Files.write(new File(selectedDirectory, "privateKey.key").toPath(), encryptedPrivateKey);

                showAlert("Éxito", "Claves generadas correctamente.");

            } catch (Exception e) {
                showAlert("Error", "Error al generar claves");
            }
        });
    }

    /**
     * Encripta o desencripta una clave privada usando una frase de contraseña.
     *
     * @param passphrase la  contraseña utilizada para encriptar la clave
     * @param privateKey la clave privada a ser encriptada o desencriptada
     * @param mode el modo del cifrado (Cipher.ENCRYPT_MODE o Cipher.DECRYPT_MODE)
     * @return la clave privada encriptada o desencriptada
     * @throws Exception si ocurre un error durante el proceso de encriptación o desencriptación
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
        if (selectedDirectory == null) {
            showAlert("Error", "Debe seleccionar un directorio primero.");
            return;
        }
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo a firmar");
        File archivo = fileChooser.showOpenDialog(null);

        //si se seleccionó un archivo para firmar
        if (archivo != null) {


            TextInputDialog dialog = new TextInputDialog();
            dialog.setTitle("Firmar Archivo");
            dialog.setHeaderText("Ingrese la contraseña de la clave privada:");

            //Si se digitó una contraseña
            dialog.showAndWait().ifPresent(passphrase -> {
                try {

                    //se lee la clave privada
                    PrivateKey privateKey = leerClavePrivada(new File(selectedDirectory.getAbsolutePath(), "privateKey.key"), passphrase.toCharArray());

                    Signature signature = Signature.getInstance("SHA256withRSA");

                    //se asigna la clave privada al objeto signature
                    signature.initSign(privateKey);

                    //se lee el archivo a firmar
                    byte[] data = Files.readAllBytes(archivo.toPath());

                    //se actualiza el objeto signature con los datos del archivo
                    signature.update(data);

                    //se firma el archivo
                    byte[] firma = signature.sign();

                    //se guarda la firma en un archivo
                    Files.write(new File(selectedDirectory, "archivo.firma").toPath(), firma);

                    showAlert("Éxito", "Archivo firmado correctamente.");
                } catch (Exception e) {
                    showAlert("Error", "Contraseña incorrecta");
                }
            });
            
        }
    }

    /**
     * Verifica la firma de un archivo seleccionado por el usuario.
     */
    private void verificarFirma() {
        if (selectedDirectory == null) {
            showAlert("Error", "Debe seleccionar un directorio primero.");
            return;
        }
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo original");

        File archivoOriginal = fileChooser.showOpenDialog(null);

        // si se seleccionó un archivo original
        if (archivoOriginal != null) {


            fileChooser.setTitle("Seleccione el archivo que contiene la firma");
            File archivoFirma = fileChooser.showOpenDialog(null);

            // si se seleccionó un archivo de firma
            if (archivoFirma != null) {

                try {
                    //se lee la clave pública
                    PublicKey publicKey = leerClavePublica(new File(selectedDirectory.getAbsolutePath(), "publicKey.key"));

                    Signature signature = Signature.getInstance("SHA256withRSA");

                    //se asigna la clave pública al objeto signature
                    signature.initVerify(publicKey);

                    // se lee el archivo original
                    byte[] data = Files.readAllBytes(archivoOriginal.toPath());
                    signature.update(data);

                    //se lee la firma
                    byte[] firma = Files.readAllBytes(archivoFirma.toPath());

                    //se verifica la firma
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

        //tipo de codificación de la clave privada
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

        //tipo de codificación de la clave pública
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