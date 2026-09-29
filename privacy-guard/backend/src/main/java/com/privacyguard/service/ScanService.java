package com.privacyguard.service;

import com.privacyguard.dto.*;
import com.privacyguard.model.*;
import com.privacyguard.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.regex.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanService {

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final UserRepository userRepository;
    private final RiskScoringService riskScoringService;

    // Known tracker fingerprints (script src patterns)
    private static final Map<String, String[]> TRACKER_SIGNATURES = Map.of(
        "Google Analytics 4",   new String[]{"googletagmanager.com/gtag", "google-analytics.com/analytics.js"},
        "Google Tag Manager",   new String[]{"googletagmanager.com/gtm.js"},
        "Meta Pixel",           new String[]{"connect.facebook.net/en_US/fbevents.js"},
        "TikTok Pixel",         new String[]{"analytics.tiktok.com"},
        "Hotjar",               new String[]{"static.hotjar.com", "script.hotjar.com"},
        "Mixpanel",             new String[]{"cdn.mxpnl.com", "cdn4.mxpnl.com"},
        "Adobe Analytics",      new String[]{"omtrdc.net", "2o7.net", "adobetagmanager.com"},
        "Segment",              new String[]{"cdn.segment.com", "cdn.segment.io"},
        "Intercom",             new String[]{"widget.intercom.io", "js.intercom.io"}
    );

    private static final Pattern EMAIL_PATTERN =
        Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern PHONE_PATTERN =
        Pattern.compile("\\b(\\+?1[\\s.-]?)?\\(?[2-9]\\d{2}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b");
    private static final Pattern API_KEY_PATTERN =
        Pattern.compile("(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|ya29\\.[0-9A-Za-z\\-_]+)");
    private static final Pattern AWS_KEY_PATTERN =
        Pattern.compile("AKIA[0-9A-Z]{16}");

    @Transactional
    public ScanResponseDto initiateScan(ScanRequestDto request, Authentication auth) {
        String sanitizedUrl = sanitizeUrl(request.getUrl());

        User user = null;
        if (auth != null && auth.isAuthenticated()) {
            user = userRepository.findByEmail(auth.getName()).orElse(null);
        }

        Scan scan = Scan.builder()
            .url(sanitizedUrl)
            .status(Scan.ScanStatus.PENDING)
            .user(user)
            .build();
        scan = scanRepository.save(scan);

        performScanAsync(scan.getId());

        return ScanResponseDto.builder()
            .scanId(scan.getId())
            .url(sanitizedUrl)
            .status("PENDING")
            .message("Scan initiated. Poll /api/results/" + scan.getId() + "/status for progress.")
            .build();
    }

    @Async("scanExecutor")
    public void performScanAsync(Long scanId) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(Scan.ScanStatus.IN_PROGRESS);
        scanRepository.save(scan);

        List<Finding> findings = new ArrayList<>();
        try {
            String url = ensureHttps(scan.getUrl());
            Document doc = fetchPage(url);

            findings.addAll(analyzeHttps(scan, url));
            findings.addAll(analyzeCookies(scan, doc, url));
            findings.addAll(analyzeForms(scan, doc, url));
            findings.addAll(analyzeTrackers(scan, doc));
            findings.addAll(analyzePrivacyPolicy(scan, doc, url));
            findings.addAll(analyzeDataExposure(scan, doc));

            int overall = riskScoringService.computeOverallScore(findings);
            int gdpr = riskScoringService.computeGdprScore(findings, scan);
            int ccpa = riskScoringService.computeCcpaScore(findings, scan);
            int coppa = riskScoringService.computeCoppaScore(findings, scan);

            scan.setOverallScore(overall);
            scan.setGdprScore(gdpr);
            scan.setCcpaScore(ccpa);
            scan.setCoppaScore(coppa);
            scan.setStatus(Scan.ScanStatus.COMPLETED);

        } catch (Exception e) {
            log.error("Scan failed for scanId={}: {}", scanId, e.getMessage(), e);
            scan.setStatus(Scan.ScanStatus.FAILED);
            scan.setErrorMessage(e.getMessage());
        }

        findings.forEach(f -> f.setScan(scan));
        findingRepository.saveAll(findings);
        scanRepository.save(scan);
    }

    // ── HTTPS Analysis ──────────────────────────────────────────────────────

    private List<Finding> analyzeHttps(Scan scan, String url) {
        List<Finding> findings = new ArrayList<>();
        boolean isHttps = url.startsWith("https://");

        if (!isHttps) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.CRITICAL)
                .category(Finding.Category.HTTPS)
                .title("No HTTPS Encryption")
                .description("The site is served over plain HTTP. All data exchanged between users and the server is transmitted in cleartext, making it vulnerable to interception (MITM attacks).")
                .recommendation("Obtain a TLS certificate (e.g., via Let's Encrypt) and enforce HTTPS. Configure HSTS to prevent protocol downgrade attacks.")
                .build());
            scan.setHttpsEnabled(false);
            scan.setSslValid(false);
        } else {
            scan.setHttpsEnabled(true);
            try {
                URL u = new URL(url);
                HttpsURLConnection conn = (HttpsURLConnection) u.openConnection();
                conn.connect();
                X509Certificate cert = (X509Certificate) conn.getServerCertificates()[0];
                Date expiry = cert.getNotAfter();
                long daysLeft = (expiry.getTime() - System.currentTimeMillis()) / 86_400_000;
                scan.setSslValid(true);
                scan.setSslExpiryDays((int) daysLeft);
                if (daysLeft < 30) {
                    findings.add(Finding.builder()
                        .severity(Finding.Severity.HIGH)
                        .category(Finding.Category.HTTPS)
                        .title("SSL Certificate Expiring Soon")
                        .description("The SSL certificate expires in " + daysLeft + " days.")
                        .recommendation("Renew the certificate immediately. Consider automated renewal via certbot.")
                        .build());
                } else {
                    findings.add(Finding.builder()
                        .severity(Finding.Severity.INFORMATIONAL)
                        .category(Finding.Category.HTTPS)
                        .title("SSL Certificate Valid")
                        .description("Certificate is valid and expires in " + daysLeft + " days.")
                        .recommendation("Monitor expiry and enable auto-renewal.")
                        .build());
                }
            } catch (Exception e) {
                scan.setSslValid(false);
                findings.add(Finding.builder()
                    .severity(Finding.Severity.HIGH)
                    .category(Finding.Category.HTTPS)
                    .title("SSL Certificate Error")
                    .description("Could not validate SSL certificate: " + e.getMessage())
                    .recommendation("Verify certificate chain and ensure intermediate certificates are configured correctly.")
                    .build());
            }
        }
        return findings;
    }

    // ── Cookie Analysis ──────────────────────────────────────────────────────

    private List<Finding> analyzeCookies(Scan scan, Document doc, String url) {
        List<Finding> findings = new ArrayList<>();

        // Check for cookie consent banner
        boolean hasBanner = !doc.select(
            "[class*=cookie-consent],[class*=cookie-banner],[id*=cookie-notice],[id*=gdpr-banner],[class*=cc-window]"
        ).isEmpty();
        scan.setCookieConsentFound(hasBanner);

        if (!hasBanner) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.HIGH)
                .category(Finding.Category.COOKIES)
                .title("Missing Cookie Consent Banner")
                .description("No cookie consent mechanism was detected. GDPR Article 7 and ePrivacy Directive require explicit user consent before setting non-essential cookies.")
                .recommendation("Implement a GDPR-compliant Consent Management Platform (CMP) such as Cookiebot, OneTrust, or Osano.")
                .build());
        }

        // Check cookies via HTTP headers
        try {
            URL u = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setRequestProperty("User-Agent", "PrivacyGuard/1.0 (+https://privacyguard.io/bot)");
            conn.connect();
            Map<String, List<String>> headers = conn.getHeaderFields();
            List<String> setCookies = headers.getOrDefault("Set-Cookie", List.of());

            int insecure = 0, noHttpOnly = 0, noExpiry = 0;
            for (String cookie : setCookies) {
                String lower = cookie.toLowerCase();
                if (!lower.contains("secure")) insecure++;
                if (!lower.contains("httponly")) noHttpOnly++;
                if (!lower.contains("expires") && !lower.contains("max-age")) noExpiry++;
            }
            if (insecure > 0) findings.add(Finding.builder()
                .severity(Finding.Severity.MEDIUM)
                .category(Finding.Category.COOKIES)
                .title(insecure + " Cookie(s) Missing Secure Flag")
                .description("Cookies without the Secure flag can be transmitted over unencrypted HTTP, exposing session data.")
                .recommendation("Add the Secure attribute to all cookies containing sensitive data.")
                .build());
            if (noHttpOnly > 0) findings.add(Finding.builder()
                .severity(Finding.Severity.MEDIUM)
                .category(Finding.Category.COOKIES)
                .title(noHttpOnly + " Cookie(s) Missing HttpOnly Flag")
                .description("Cookies without HttpOnly are accessible via JavaScript, increasing XSS attack surface.")
                .recommendation("Set HttpOnly on all cookies that do not require JavaScript access.")
                .build());
            if (noExpiry > 0) findings.add(Finding.builder()
                .severity(Finding.Severity.LOW)
                .category(Finding.Category.COOKIES)
                .title(noExpiry + " Cookie(s) Without Expiration")
                .description("Cookies without Max-Age or Expires persist until the browser is closed, potentially longer than intended.")
                .recommendation("Set explicit expiration dates consistent with the data retention policy.")
                .build());
        } catch (IOException e) {
            log.warn("Could not inspect response headers for {}: {}", url, e.getMessage());
        }
        return findings;
    }

    // ── Form Analysis ────────────────────────────────────────────────────────

    private List<Finding> analyzeForms(Scan scan, Document doc, String url) {
        List<Finding> findings = new ArrayList<>();
        Elements forms = doc.select("form");

        for (Element form : forms) {
            String action = form.attr("action").toLowerCase();
            boolean submitsOverHttp = action.startsWith("http://");

            Set<String> sensitiveFields = new HashSet<>();
            for (Element input : form.select("input,select,textarea")) {
                String name = (input.attr("name") + " " + input.attr("id") + " " + input.attr("placeholder")).toLowerCase();
                if (name.matches(".*\\b(email|mail)\\b.*")) sensitiveFields.add("email");
                if (name.matches(".*\\b(phone|tel|mobile)\\b.*")) sensitiveFields.add("phone");
                if (name.matches(".*\\b(address|street|city|zip|postal)\\b.*")) sensitiveFields.add("address");
                if (name.matches(".*\\b(birth|dob|age)\\b.*")) sensitiveFields.add("date_of_birth");
                if (name.matches(".*\\b(card|cvv|credit|payment)\\b.*")) sensitiveFields.add("payment");
                if (name.matches(".*\\b(ssn|social.?security|national.?id)\\b.*")) sensitiveFields.add("ssn");
            }

            if (submitsOverHttp) {
                findings.add(Finding.builder()
                    .severity(Finding.Severity.CRITICAL)
                    .category(Finding.Category.FORMS)
                    .title("Form Submits Data Over HTTP")
                    .description("A form with action=\"" + action + "\" submits user data over unencrypted HTTP.")
                    .recommendation("Change the form action to an HTTPS endpoint. Enforce HTTPS site-wide.")
                    .build());
            }

            if (sensitiveFields.size() >= 4) {
                findings.add(Finding.builder()
                    .severity(Finding.Severity.MEDIUM)
                    .category(Finding.Category.FORMS)
                    .title("Excessive Data Collection Detected")
                    .description("A form collects: " + String.join(", ", sensitiveFields) + ". This may violate data minimization principles under GDPR Article 5(1)(c).")
                    .recommendation("Review and justify each data field. Collect only data strictly necessary for the stated purpose.")
                    .build());
            }

            if (sensitiveFields.contains("payment")) {
                findings.add(Finding.builder()
                    .severity(Finding.Severity.HIGH)
                    .category(Finding.Category.FORMS)
                    .title("Payment Data Collection Detected")
                    .description("A form appears to collect payment information. Ensure PCI DSS compliance and consider delegating to a certified payment processor.")
                    .recommendation("Use a PCI DSS Level 1 certified payment processor (Stripe, Braintree). Never store raw card numbers.")
                    .build());
            }
        }
        return findings;
    }

    // ── Tracker Detection ────────────────────────────────────────────────────

    private List<Finding> analyzeTrackers(Scan scan, Document doc) {
        List<Finding> findings = new ArrayList<>();
        String pageContent = doc.html().toLowerCase();
        List<String> detected = new ArrayList<>();

        TRACKER_SIGNATURES.forEach((name, patterns) -> {
            for (String pattern : patterns) {
                if (pageContent.contains(pattern)) {
                    detected.add(name);
                    break;
                }
            }
        });

        if (!detected.isEmpty()) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.HIGH)
                .category(Finding.Category.TRACKERS)
                .title(detected.size() + " Third-Party Tracker(s) Detected")
                .description("Trackers detected: " + String.join(", ", detected) +
                    ". Loading these before user consent violates GDPR's requirement for consent prior to data processing.")
                .recommendation("Gate all tracking scripts behind a consent management platform. Implement tag firing rules conditioned on consent categories.")
                .evidence(String.join(",", detected))
                .build());
        }
        return findings;
    }

    // ── Privacy Policy Detection ─────────────────────────────────────────────

    private List<Finding> analyzePrivacyPolicy(Scan scan, Document doc, String baseUrl) {
        List<Finding> findings = new ArrayList<>();

        boolean hasPrivacy = !doc.select("a[href*=privacy],a[href*=privacy-policy],a:contains(Privacy Policy),a:contains(Privacy Notice)").isEmpty();
        boolean hasCookie = !doc.select("a[href*=cookie],a:contains(Cookie Policy),a:contains(Cookie Notice)").isEmpty();
        boolean hasTos = !doc.select("a[href*=terms],a[href*=tos],a:contains(Terms of Service),a:contains(Terms & Conditions)").isEmpty();

        scan.setPrivacyPolicyFound(hasPrivacy);
        scan.setCookiePolicyFound(hasCookie);

        if (!hasPrivacy) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.HIGH)
                .category(Finding.Category.POLICY)
                .title("Privacy Policy Not Found")
                .description("No privacy policy page or link was detected. A privacy policy is legally required under GDPR, CCPA, COPPA, and most national privacy laws.")
                .recommendation("Create a comprehensive privacy policy disclosing: data categories collected, processing purposes, legal basis, retention periods, user rights, and DPA contact information.")
                .build());
        }
        if (!hasCookie) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.MEDIUM)
                .category(Finding.Category.POLICY)
                .title("Cookie Policy Not Found")
                .description("No cookie policy detected. Sites using cookies in the EU must maintain a cookie policy listing all cookies, their purpose, and retention period.")
                .recommendation("Publish a cookie policy and link it from the consent banner and privacy policy.")
                .build());
        }
        if (!hasTos) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.LOW)
                .category(Finding.Category.POLICY)
                .title("Terms of Service Not Found")
                .description("No Terms of Service link detected. ToS helps establish lawful basis for data processing under legitimate interest or contractual necessity.")
                .recommendation("Publish Terms of Service clearly accessible from all pages.")
                .build());
        }
        return findings;
    }

    // ── Data Exposure ────────────────────────────────────────────────────────

    private List<Finding> analyzeDataExposure(Scan scan, Document doc) {
        List<Finding> findings = new ArrayList<>();
        String source = doc.html();

        Matcher apiKeyMatcher = API_KEY_PATTERN.matcher(source);
        if (apiKeyMatcher.find()) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.CRITICAL)
                .category(Finding.Category.EXPOSURE)
                .title("API Key Exposed in Page Source")
                .description("A sensitive API key pattern was found in the page HTML/JavaScript. Exposed keys can be abused to make unauthorized API calls incurring costs or data breaches.")
                .recommendation("Remove the key from frontend code immediately. Rotate the key. Use server-side proxy endpoints and restrict API key scope.")
                .evidence(apiKeyMatcher.group().substring(0, Math.min(8, apiKeyMatcher.group().length())) + "***")
                .build());
        }

        Matcher emailMatcher = EMAIL_PATTERN.matcher(source);
        Set<String> emails = new HashSet<>();
        while (emailMatcher.find()) emails.add(emailMatcher.group());
        emails.removeIf(e -> e.endsWith(".png") || e.endsWith(".jpg") || e.contains("@example") || e.contains("@test"));

        if (!emails.isEmpty()) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.MEDIUM)
                .category(Finding.Category.EXPOSURE)
                .title("Email Address(es) Exposed in Source")
                .description(emails.size() + " email address(es) found in page source, making them easily harvestable by spam bots and scrapers.")
                .recommendation("Use contact forms instead of mailto links. If email display is necessary, use JavaScript obfuscation or image-based rendering.")
                .build());
        }

        if (AWS_KEY_PATTERN.matcher(source).find()) {
            findings.add(Finding.builder()
                .severity(Finding.Severity.CRITICAL)
                .category(Finding.Category.EXPOSURE)
                .title("AWS Access Key Exposed")
                .description("An AWS access key ID (AKIA...) was found in the page source. This represents a critical security vulnerability.")
                .recommendation("Immediately revoke the key in IAM. Remove from source. Use IAM roles and environment variables for credentials.")
                .build());
        }
        return findings;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private Document fetchPage(String url) throws IOException {
        return Jsoup.connect(url)
            .userAgent("PrivacyGuard/1.0 (+https://privacyguard.io/bot)")
            .timeout(15_000)
            .followRedirects(true)
            .get();
    }

    private String sanitizeUrl(String url) {
        url = url.trim().toLowerCase();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        try {
            URI uri = new URI(url);
            if (uri.getHost() == null) throw new IllegalArgumentException("Invalid URL: " + url);
            // Block private/internal ranges
            String host = uri.getHost();
            if (host.equals("localhost") || host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.")) {
                throw new SecurityException("Scanning internal/private addresses is not permitted.");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Malformed URL: " + url);
        }
        return url;
    }

    private String ensureHttps(String url) {
        return url.startsWith("http://") ? url : "https://" + url.replaceFirst("^https?://", "");
    }

    // ── Query Methods ────────────────────────────────────────────────────────

    public ScanResultDto getScanResult(Long scanId, Authentication auth) {
        Scan scan = scanRepository.findByIdWithFindings(scanId)
            .orElseThrow(() -> new NoSuchElementException("Scan not found: " + scanId));
        checkOwnership(scan, auth);
        return ScanResultDto.from(scan);
    }

    public ScanStatusDto getScanStatus(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new NoSuchElementException("Scan not found: " + scanId));
        return new ScanStatusDto(scanId, scan.getStatus().name(), scan.getErrorMessage());
    }

    public List<ScanSummaryDto> getUserScans(int page, int size, Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) return List.of();
        User user = userRepository.findByEmail(auth.getName()).orElseThrow();
        return scanRepository.findByUserOrderByScanDateDesc(user)
            .stream().skip((long) page * size).limit(size).map(ScanSummaryDto::from).toList();
    }

    @Transactional
    public void deleteScan(Long scanId, Authentication auth) {
        Scan scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new NoSuchElementException("Scan not found: " + scanId));
        checkOwnership(scan, auth);
        scanRepository.delete(scan);
    }

    private void checkOwnership(Scan scan, Authentication auth) {
        if (auth == null) return;
        if (scan.getUser() != null && !scan.getUser().getEmail().equals(auth.getName())) {
            throw new AccessDeniedException("Access denied");
        }
    }
}
