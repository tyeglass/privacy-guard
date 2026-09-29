package com.privacyguard.service;

import com.privacyguard.model.Finding;
import com.privacyguard.model.Scan;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskScoringService {

    private static final int CRITICAL_PENALTY = 25;
    private static final int HIGH_PENALTY     = 15;
    private static final int MEDIUM_PENALTY   = 8;
    private static final int LOW_PENALTY      = 3;

    public int computeOverallScore(List<Finding> findings) {
        int score = 100;
        for (Finding f : findings) {
            score -= switch (f.getSeverity()) {
                case CRITICAL      -> CRITICAL_PENALTY;
                case HIGH          -> HIGH_PENALTY;
                case MEDIUM        -> MEDIUM_PENALTY;
                case LOW           -> LOW_PENALTY;
                case INFORMATIONAL -> 0;
            };
        }
        return Math.max(0, Math.min(100, score));
    }

    public int computeGdprScore(List<Finding> findings, Scan scan) {
        int score = 100;
        // GDPR heavily penalizes: consent, policy, https, trackers, data minimization
        for (Finding f : findings) {
            if (f.getCategory() == Finding.Category.COOKIES && f.getSeverity() == Finding.Severity.HIGH) score -= 20;
            if (f.getCategory() == Finding.Category.TRACKERS) score -= 15;
            if (f.getCategory() == Finding.Category.POLICY && f.getSeverity() == Finding.Severity.HIGH) score -= 18;
            if (f.getCategory() == Finding.Category.HTTPS && f.getSeverity() == Finding.Severity.CRITICAL) score -= 20;
            if (f.getCategory() == Finding.Category.EXPOSURE) score -= 10;
            if (f.getCategory() == Finding.Category.FORMS && f.getSeverity() == Finding.Severity.MEDIUM) score -= 8;
            if (f.getCategory() == Finding.Category.COOKIES && f.getSeverity() == Finding.Severity.MEDIUM) score -= 5;
        }
        return Math.max(0, Math.min(100, score));
    }

    public int computeCcpaScore(List<Finding> findings, Scan scan) {
        int score = 100;
        // CCPA focuses on: right to opt-out, privacy notice, data disclosure
        for (Finding f : findings) {
            if (f.getCategory() == Finding.Category.POLICY && f.getSeverity() == Finding.Severity.HIGH) score -= 20;
            if (f.getCategory() == Finding.Category.TRACKERS) score -= 10;
            if (f.getCategory() == Finding.Category.EXPOSURE) score -= 15;
            if (f.getCategory() == Finding.Category.FORMS && f.getSeverity() == Finding.Severity.HIGH) score -= 10;
            if (f.getCategory() == Finding.Category.HTTPS && f.getSeverity() == Finding.Severity.CRITICAL) score -= 15;
            if (f.getCategory() == Finding.Category.COOKIES && f.getSeverity() == Finding.Severity.HIGH) score -= 12;
        }
        return Math.max(0, Math.min(100, score));
    }

    public int computeCoppaScore(List<Finding> findings, Scan scan) {
        int score = 100;
        // COPPA: child-directed sites must not collect PII from children under 13
        for (Finding f : findings) {
            if (f.getCategory() == Finding.Category.FORMS && f.getTitle().toLowerCase().contains("birth")) score -= 20;
            if (f.getCategory() == Finding.Category.POLICY && f.getSeverity() == Finding.Severity.HIGH) score -= 15;
            if (f.getCategory() == Finding.Category.TRACKERS) score -= 8;
            if (f.getCategory() == Finding.Category.EXPOSURE) score -= 10;
            if (f.getCategory() == Finding.Category.HTTPS && f.getSeverity() == Finding.Severity.CRITICAL) score -= 20;
        }
        return Math.max(0, Math.min(100, score));
    }
}
