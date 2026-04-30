package org.CI536.analyser.ui;

import javafx.animation.AnimationTimer;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import javafx.util.StringConverter;
import org.CI536.analyser.capture.CaptureEngine;
import org.CI536.analyser.parser.PacketDetails;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.SimpleObjectProperty;


import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

public class PacketTableView extends Application {

    public static final ConcurrentLinkedQueue<PacketDetails> packetQueue = new ConcurrentLinkedQueue<>();
    private final TableView<PacketDetails> table = new TableView<>();

    @Override
    public void start(Stage stage) {
        stage.setTitle("Java Network Analyzer");
        stage.setWidth(900);
        stage.setHeight(600);

        final Label label = new Label("Live Packet Capture");
        label.setFont(new Font("Open Sans", 20));

        ComboBox<PcapNetworkInterface> deviceComboBox = new ComboBox<>();
        deviceComboBox.setPrefWidth(400);
        deviceComboBox.setPromptText("Select a Network Interface...");

        // Load the devices into the ComboBox
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            deviceComboBox.getItems().addAll(allDevs);
        } catch (Exception e) {
            System.err.println("Could not load devices. Are you running as Administrator?");
        }

        deviceComboBox.setConverter(new StringConverter<>() {
            @Override
            public String toString(PcapNetworkInterface device) {
                if (device == null) return "";
                String description = device.getDescription() != null ? device.getDescription() : device.getName();

                // Add the IP address to the label if it has one
                if (!device.getAddresses().isEmpty()) {
                    description += " (" + device.getAddresses().getFirst().getAddress().getHostAddress() + ")";
                }
                return description;
            }

            @Override
            public PcapNetworkInterface fromString(String string) {
                return null; // Not needed
            }
        });

        Button startButton = new Button("Start Capture");
        Button stopButton = new Button("Stop Capture");
        stopButton.setDisable(true); // Disabled until capture starts

        HBox controlBar = new HBox(10); // 10px spacing between elements
        controlBar.getChildren().addAll(deviceComboBox, startButton, stopButton);


        // --- 2. BUTTON ACTIONS ---
        startButton.setOnAction(event -> {
            PcapNetworkInterface selectedDevice = deviceComboBox.getValue();
            if (selectedDevice == null) {
                // Show a quick warning if they didn't pick anything
                Alert alert = new Alert(Alert.AlertType.WARNING, "Please select a network interface first!");
                alert.show();
                return;
            }

            // Clear old data from the UI
            table.getItems().clear();
            packetQueue.clear();

            // Toggle button states
            startButton.setDisable(true);
            deviceComboBox.setDisable(true);
            stopButton.setDisable(false);

            // Launch the capture in a background thread!
            Thread captureThread = new Thread(() -> {
                try {
                    CaptureEngine.startCapture(selectedDevice);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            captureThread.setDaemon(true);
            captureThread.start();
        });

        stopButton.setOnAction(event -> {
            CaptureEngine.stopCapture();

            // Reset UI buttons
            startButton.setDisable(false);
            deviceComboBox.setDisable(false);
            stopButton.setDisable(true);
        });
        TableColumn<PacketDetails, String> countCol = new TableColumn<>("No.");
        countCol.setCellValueFactory(cellData -> new SimpleObjectProperty<>(cellData.getValue().count()).asString());
        countCol.setPrefWidth(120);

        TableColumn<PacketDetails, String> timestampCol = new TableColumn<>("Time");
        timestampCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().timestamp()));
        timestampCol.setPrefWidth(120);

        TableColumn<PacketDetails, String> srcCol = new TableColumn<>("Source IP");
        srcCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().sourceIp()));
        srcCol.setPrefWidth(150);

        TableColumn<PacketDetails, String> dstCol = new TableColumn<>("Destination IP");
        dstCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().destinationIp()));
        dstCol.setPrefWidth(150);

        TableColumn<PacketDetails, String> protocolCol = new TableColumn<>("Protocol");
        protocolCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().protocol()));
        protocolCol.setPrefWidth(100);

        TableColumn<PacketDetails, Integer> lengthCol = new TableColumn<>("Length");
        // Note: SimpleObjectProperty is used here because length is an Integer, not a String
        lengthCol.setCellValueFactory(cellData -> new SimpleObjectProperty<>(cellData.getValue().length()));
        lengthCol.setPrefWidth(80);

        table.getColumns().addAll(countCol, timestampCol, srcCol, dstCol, protocolCol, lengthCol);


        final VBox vbox = new VBox(10); // 10px spacing
        vbox.setPadding(new Insets(10));
        VBox.setVgrow(table, Priority.ALWAYS);

        vbox.getChildren().addAll(label, controlBar, table);

        Scene scene = new Scene(vbox);
        stage.setScene(scene);

        stage.setOnCloseRequest(event -> CaptureEngine.stopCapture());
        stage.show();


        AnimationTimer timer = new AnimationTimer() {
            @Override
            public void handle(long now) {
                // Batch add up to 50 packets per frame to keep UI responsive
                int count = 0;
                while (!packetQueue.isEmpty() && count < 50) {
                    table.getItems().add(packetQueue.poll());
                    count++;
                }
            }
        };
        timer.start();
    }

    public static void main(String[] args) {
        launch(args);
    }
}