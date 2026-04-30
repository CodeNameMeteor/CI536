package org.CI536.analyser;

import javafx.application.Application;
import org.CI536.analyser.ui.PacketTableView;

public class Main {

    public static void main(String[] args) {
        System.out.println("Starting Java Network Analyzer...");


        Application.launch(PacketTableView.class, args);
    }
}