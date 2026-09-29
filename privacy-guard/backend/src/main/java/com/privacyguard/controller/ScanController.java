package com.privacyguard.controller;

import com.privacyguard.dto.*;
import com.privacyguard.service.ScanService;
import com.privacyguard.service.ReportService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "${app.cors.allowed-origins}")
public class ScanController {

    private final ScanService scanService;
    private final ReportService reportService;

    /**
     * POST /api/scan
     * Initiates a new privacy scan for the provided URL.
     */
    @PostMapping("/scan")
    public ResponseEntity<ScanResponseDto> startScan(
            @Valid @RequestBody ScanRequestDto request,
            Authentication auth) {
        ScanResponseDto response = scanService.initiateScan(request, auth);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    /**
     * GET /api/results/{scanId}
     * Returns full scan results including all findings.
     */
    @GetMapping("/results/{scanId}")
    public ResponseEntity<ScanResultDto> getScanResults(
            @PathVariable Long scanId,
            Authentication auth) {
        ScanResultDto result = scanService.getScanResult(scanId, auth);
        return ResponseEntity.ok(result);
    }

    /**
     * GET /api/results/{scanId}/status
     * Lightweight endpoint to poll scan progress.
     */
    @GetMapping("/results/{scanId}/status")
    public ResponseEntity<ScanStatusDto> getScanStatus(@PathVariable Long scanId) {
        ScanStatusDto status = scanService.getScanStatus(scanId);
        return ResponseEntity.ok(status);
    }

    /**
     * GET /api/report/{scanId}
     * Downloads the scan report in the requested format (pdf or json).
     */
    @GetMapping("/report/{scanId}")
    public ResponseEntity<byte[]> downloadReport(
            @PathVariable Long scanId,
            @RequestParam(defaultValue = "pdf") String format,
            Authentication auth) {

        byte[] reportBytes = reportService.generateReport(scanId, format, auth);

        String contentType = "pdf".equalsIgnoreCase(format)
                ? "application/pdf"
                : "application/json";
        String filename = "privacy-report-" + scanId + "." + format;

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.parseMediaType(contentType))
                .body(reportBytes);
    }

    /**
     * GET /api/scans
     * Returns paginated list of scans for the authenticated user.
     */
    @GetMapping("/scans")
    public ResponseEntity<List<ScanSummaryDto>> getUserScans(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication auth) {
        return ResponseEntity.ok(scanService.getUserScans(page, size, auth));
    }

    /**
     * DELETE /api/scans/{scanId}
     * Deletes a scan and all associated findings.
     */
    @DeleteMapping("/scans/{scanId}")
    public ResponseEntity<Void> deleteScan(
            @PathVariable Long scanId,
            Authentication auth) {
        scanService.deleteScan(scanId, auth);
        return ResponseEntity.noContent().build();
    }
}
