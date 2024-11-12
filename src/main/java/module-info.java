module org.example.proyecto_ciber {
    requires javafx.controls;
    requires javafx.fxml;


    opens org.example.proyecto_ciber to javafx.fxml;
    exports org.example.proyecto_ciber;
}