package com.privacyguard.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "findings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Category category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false, length = 500)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String recommendation;

    @Column(length = 2048)
    private String evidence;

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    }

    public enum Category {
        HTTPS, COOKIES, FORMS, TRACKERS, POLICY, EXPOSURE, COMPLIANCE
    }
}
