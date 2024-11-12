package org.example.proyecto_ciber;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextInputDialog;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class HelloApplication extends Application {

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Firmador y Verificador de Firmas Digitales");

        Button btnGenerarClaves = new Button("Generar par de claves RSA");
        Button btnFirmarArchivo = new Button("Firmar archivo");
        Button btnVerificarFirma = new Button("Verificar firma");

        btnGenerarClaves.setOnAction(e -> generarClaves());
        btnFirmarArchivo.setOnAction(e -> firmarArchivo());
        btnVerificarFirma.setOnAction(e -> verificarFirma());

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(20));
        layout.getChildren().addAll(btnGenerarClaves, btnFirmarArchivo, btnVerificarFirma);

        Scene scene = new Scene(layout, 400, 200);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void generarClaves() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Generar Claves");
        dialog.setHeaderText("Ingrese una contraseña para proteger la clave privada:");
        dialog.showAndWait().ifPresent(passphrase -> {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();

                Files.write(new File("publicKey.key").toPath(), pair.getPublic().getEncoded());

                Files.write(new File("privateKey.key").toPath(), pair.getPrivate().getEncoded());

                showAlert("Éxito", "Claves generadas y guardadas correctamente.");
            } catch (Exception e) {
                showAlert("Error", "Error al generar claves: " + e.getMessage());
            }
        });
    }

    private void firmarArchivo() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo a firmar");

        File archivo = fileChooser.showOpenDialog(null);
        if (archivo != null) {
            String archivoClavePrivada = "privateKey.key";
            try {
                PrivateKey privateKey = leerClavePrivada(archivoClavePrivada);

                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);

                byte[] data = Files.readAllBytes(archivo.toPath());
                signature.update(data);

                byte[] firma = signature.sign();
                Files.write(new File("archivo.firma").toPath(), firma);

                showAlert("Éxito", "Archivo firmado correctamente.");
            } catch (Exception e) {
                showAlert("Error", "Error al firmar archivo: " + e.getMessage());
            }
        }
    }

    private void verificarFirma() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Seleccione el archivo original");

        File archivoOriginal = fileChooser.showOpenDialog(null);
        if (archivoOriginal != null) {
            String archivoClavePublica = "publicKey.key";
            String archivoFirma = "archivo.firma";
            try {
                PublicKey publicKey = leerClavePublica(archivoClavePublica);

                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);

                byte[] data = Files.readAllBytes(archivoOriginal.toPath());
                signature.update(data);

                 byte[] firma = Files.readAllBytes(new File(archivoFirma).toPath());
                boolean esValida = signature.verify(firma);

                showAlert("Resultado", "¿La firma es válida? " + esValida);
            } catch (Exception e) {
                showAlert("Error", "Error al verificar firma: " + e.getMessage());
            }
        }
    }

    private PrivateKey leerClavePrivada(String archivoClavePrivada) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(archivoClavePrivada).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private PublicKey leerClavePublica(String archivoClavePublica) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(archivoClavePublica).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

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