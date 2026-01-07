package com.qualys.plugins.scanner.runner;

import com.qualys.plugins.scanner.types.QScannerResult;

import java.io.IOException;

public interface ScannerRunner {

    void setup() throws IOException, InterruptedException;

    QScannerResult scanImage() throws IOException, InterruptedException;

    QScannerResult scanRepo() throws IOException, InterruptedException;

    QScannerResult scanRootfs() throws IOException, InterruptedException;

    String getBackendName();

    boolean supportsScanType(String scanType);
}
