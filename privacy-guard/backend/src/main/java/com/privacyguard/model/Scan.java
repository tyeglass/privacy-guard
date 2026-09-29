package com.privacyguard.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scans")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 2048)
    private String url;

    @CreationTimestamp
    @Column(name = "scan_date", nullable = false, updatable = false)
    private LocalDateTime scanDate;

    @Column(name = "overall_score")
    private Integer overallScore;

    @Column(name = "gdpr_score")
    private Integer gdprScore;

    @Column(name = "ccpa_score")
    private Integer ccpaScore;

    @Column(name = "coppa_score")
    private Integer coppaScore;

    @Column(name = "https_enabled")
    private Boolean httpsEnabled;

    @Column(name = "ssl_valid")
    private Boolean sslValid;

    @Column(name = "ssl_expiry_days")
    private Integer sslExpiryDays;

    @Column(name = "privacy_policy_found")
    private Boolean privacyPolicyFound;

    @Column(name = "cookie_policy_found")
    private Boolean cookiePolicyFound;

    @Column(name = "cookie_consent_found")
    private Boolean cookieConsentFound;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_status")
    private ScanStatus status;

    @Column(name = "error_message")
    private String errorMessage;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Finding> findings = new ArrayList<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    public enum ScanStatus {
        PENDING, IN_PROGRESS, COMPLETED, FAILED
    }
}
