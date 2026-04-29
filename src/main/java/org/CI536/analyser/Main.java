package org.CI536.analyser;

import javafx.application.Application;
import org.CI536.analyser.ui.PacketTableView;

public class Main {

    public static void main(String[] args) {
        System.out.println("Starting Java Network Analyzer...");

        // This is the magic bridge!
        // It tells the Java virtual machine to boot up the JavaFX environment
        // and immediately launch your PacketTableView class.
        Application.launch(PacketTableView.class, args);
    }
}