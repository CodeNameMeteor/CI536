package org.CI536.analyser; // Make sure this matches your project

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import org.CI536.analyser.capture.CaptureEngine;

import java.net.SocketException;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Create a simple label
        Label helloLabel = new Label("Packet Analyzer Ready!");

        // Add it to a basic layout
        StackPane root = new StackPane();
        root.getChildren().add(helloLabel);

        // Create the scene (window content)
        Scene scene = new Scene(root, 800, 600);

        // Configure and show the window
        primaryStage.setTitle("Java Packet Sniffer");
        primaryStage.setScene(scene);
        primaryStage.show();

        CaptureEngine.startCapture();

    }

    static void main(String[] args) throws Exception {
        // This launches the JavaFX application lifecycle
        launch(args);
    }
}