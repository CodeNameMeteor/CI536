package org.CI536.analyser.ui;

import javafx.animation.AnimationTimer;
import javafx.application.Application;

import javafx.collections.ListChangeListener;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import javafx.util.StringConverter;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import org.CI536.analyser.capture.CaptureEngine;
import org.CI536.analyser.parser.PacketDetails;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.SimpleObjectProperty;

import javafx.stage.FileChooser;

import java.io.File;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;


public class PacketTableView extends Application {

    public static final ConcurrentLinkedQueue<PacketDetails> packetQueue = new ConcurrentLinkedQueue<>();
    private final TableView<PacketDetails> table = new TableView<>();

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        stage.setTitle("Mocha");
        stage.setWidth(1200);
        stage.setHeight(600);


        stage.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("/mocha.png"))));


        final Label label = new Label("Mocha");
        label.setFont(new Font("Open Sans", 20));

        ComboBox<PcapNetworkInterface> deviceComboBox = new ComboBox<>();
        deviceComboBox.setPrefWidth(400);
        deviceComboBox.setPromptText("Select a Network Interface...");

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

                if (!device.getAddresses().isEmpty()) {
                    description += " (" + device.getAddresses().getFirst().getAddress().getHostAddress() + ")";
                }
                return description;
            }

            @Override
            public PcapNetworkInterface fromString(String string) {
                return null;
            }
        });

        Button startButton = new Button("Start");
        Button stopButton = new Button("Stop");

        Button saveButton = new Button("Save Capture");
        Button loadButton = new Button("Load Capture");

        CheckBox autoScroll = new CheckBox("Enable Auto Scroll");

        saveButton.setDisable(true);
        stopButton.setDisable(true);

        Separator separator1 = new Separator(javafx.geometry.Orientation.VERTICAL);
        Separator separator2 = new Separator(javafx.geometry.Orientation.VERTICAL);

        HBox controlBar = new HBox(10);
        HBox filterBar = new HBox(10);

        ObservableList<PacketDetails> masterData = FXCollections.observableArrayList();

        FilteredList<PacketDetails> filteredData = new FilteredList<>(masterData, p -> true);

        SortedList<PacketDetails> sortedData = new SortedList<>(filteredData);
        sortedData.comparatorProperty().bind(table.comparatorProperty());

        table.setItems(sortedData);

        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);


        TextField searchField = new TextField();
        searchField.setPromptText("Filter by IP, Protocol, or Data...");
        searchField.setPrefWidth(500);

        searchField.textProperty().addListener((observable, oldValue, newValue) -> {

            filteredData.setPredicate(packet -> {

                if (newValue == null || newValue.isEmpty()) {
                    return true;
                }

                String lowerCaseFilter = newValue.toLowerCase();

                if (packet.protocol() != null && packet.protocol().toLowerCase().contains(lowerCaseFilter)) {
                    return true;
                } else if (packet.sourceIp() != null && packet.sourceIp().toLowerCase().contains(lowerCaseFilter)) {
                    return true;
                } else if (packet.destinationIp() != null && packet.destinationIp().toLowerCase().contains(lowerCaseFilter)) {
                    return true;
                } else if (packet.appData() != null && packet.appData().toLowerCase().contains(lowerCaseFilter)) {
                    return true;
                }else{
                    return false;
                }
            });
        });
        table.getItems().addListener((ListChangeListener<PacketDetails>) c -> {
            if (autoScroll.isSelected()) {
                table.scrollTo(table.getItems().size() - 1);
            }
        });

        controlBar.getChildren().addAll(deviceComboBox, startButton, stopButton, separator1, saveButton, loadButton, separator2, autoScroll);
        filterBar.getChildren().addAll(searchField);
        startButton.setOnAction(event -> {
            PcapNetworkInterface selectedDevice = deviceComboBox.getValue();
            if (selectedDevice == null) return;

            masterData.clear();
            packetQueue.clear();

            startButton.setDisable(true);
            saveButton.setDisable(true);
            loadButton.setDisable(true);
            deviceComboBox.setDisable(true);
            stopButton.setDisable(false);

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
            startButton.setDisable(false);

            saveButton.setDisable(false);

            loadButton.setDisable(false);
            deviceComboBox.setDisable(false);
            stopButton.setDisable(true);
        });

        saveButton.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Capture As...");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP Files", "*.pcap"));
            File saveFile = fileChooser.showSaveDialog(stage);

            if (saveFile == null) return;


            CaptureEngine.saveCaptureToFile(saveFile);

            Alert alert = new Alert(Alert.AlertType.INFORMATION, "Capture successfully saved to: " + saveFile.getName());
            alert.show();
        });

        loadButton.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open PCAP File");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP Files", "*.pcap", "*.pcapng"));
            File loadFile = fileChooser.showOpenDialog(stage);
            if (loadFile == null) return;

            masterData.clear();

            packetQueue.clear();

            Thread loadThread = new Thread(() -> {

                CaptureEngine.loadOfflinePcap(loadFile.getAbsolutePath());

            });
            loadThread.setDaemon(true);
            loadThread.start();
        });

        TableColumn<PacketDetails, String> countCol = new TableColumn<>("No.");
        countCol.setCellValueFactory(cellData -> new SimpleObjectProperty<>(cellData.getValue().packetNumber()).asString());
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
        lengthCol.setCellValueFactory(cellData -> new SimpleObjectProperty<>(cellData.getValue().length()));
        lengthCol.setPrefWidth(80);


        TableColumn<PacketDetails, String> appDataCol = new TableColumn<>("Data");
        appDataCol.setCellValueFactory(cellData -> new javafx.beans.property.SimpleStringProperty(cellData.getValue().appData()));
        appDataCol.setPrefWidth(120);

        table.getColumns().addAll(countCol, timestampCol, srcCol, dstCol, protocolCol, lengthCol, appDataCol);

        table.setRowFactory(tv -> {
            TableRow<PacketDetails> row = new TableRow<>() {
                @Override
                protected void updateItem(PacketDetails item, boolean empty) {
                    super.updateItem(item, empty);

                    if (item == null || empty) {
                        setStyle("");
                    } else {
                        String proto = item.protocol().toUpperCase();

                        if (proto.contains("TCP")) {
                            setStyle("-fx-background-color: #e7f6d5;");
                        } else if (proto.contains("UDP")) {
                            setStyle("-fx-background-color: #daeeff;");
                        } else if (proto.contains("ICMP")) {
                            setStyle("-fx-background-color: #fce0ff;");
                        } else if (proto.contains("HTTP")) {
                            setStyle("-fx-background-color: #FFC5D3;");
                        } else if (proto.contains("HTTPS")) {
                            setStyle("-fx-background-color: #E2E2E2;");
                        } else if (proto.contains("DNS")) {
                            setStyle("-fx-background-color: #E7E6FF;");
                        } else {
                            setStyle("");
                        }
                    }
                }
            };

            ContextMenu contextMenu = new ContextMenu();

            MenuItem copysrcIpItem = new MenuItem("Copy Source IP");
            copysrcIpItem.setOnAction(event -> {
                if (!row.isEmpty() && row.getItem() != null) {
                    javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
                    content.putString(row.getItem().sourceIp());
                    javafx.scene.input.Clipboard.getSystemClipboard().setContent(content);
                }
            });
            MenuItem copydstIpItem = new MenuItem("Copy Destination IP");
            copydstIpItem.setOnAction(event -> {
                if (!row.isEmpty() && row.getItem() != null) {
                    javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
                    content.putString(row.getItem().destinationIp());
                    javafx.scene.input.Clipboard.getSystemClipboard().setContent(content);
                }
            });

            MenuItem quickSourceFilterItem = new MenuItem("Filter by Source IP");
            quickSourceFilterItem.setOnAction(event -> {
                if (!row.isEmpty() && row.getItem() != null) {
                    searchField.setText(row.getItem().sourceIp());
                }
            });
            MenuItem quickDestFilterItem = new MenuItem("Filter by Destination IP");
            quickDestFilterItem.setOnAction(event -> {
                if (!row.isEmpty() && row.getItem() != null) {
                    searchField.setText(row.getItem().destinationIp());
                }
            });

            contextMenu.getItems().addAll(copysrcIpItem,copydstIpItem, quickSourceFilterItem,quickDestFilterItem);

            row.contextMenuProperty().bind(
                    javafx.beans.binding.Bindings.when(row.emptyProperty())
                            .then((ContextMenu) null)
                            .otherwise(contextMenu)
            );

            return row;
        });

        final VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(10));
        VBox.setVgrow(table, Priority.ALWAYS);

        vbox.getChildren().addAll(label, controlBar, filterBar, table);

        Scene scene = new Scene(vbox);
        stage.setScene(scene);

        stage.setOnCloseRequest(event -> CaptureEngine.stopCapture());
        stage.show();


        AnimationTimer timer = new AnimationTimer() {
            @Override
            public void handle(long now) {
                int count = 0;
                while (!packetQueue.isEmpty() && count < 50) {
                    masterData.add(packetQueue.poll());
                    count++;
                }
            }
        };
        timer.start();
    }
}