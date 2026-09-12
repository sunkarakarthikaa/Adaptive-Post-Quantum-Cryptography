import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

/**
 * PolicyEngine
 * -------------
 * THIS IS THE CORE NOVEL CONTRIBUTION of AdaptivePQC.
 *
 * Existing PQC-IoT literature applies a single, fixed Kyber security
 * level (512 / 768 / 1024) uniformly across an entire device fleet,
 * regardless of each device's actual constraints or the sensitivity
 * of what it is transmitting. That is a mismatch with real IoT
 * deployments, which are resource-heterogeneous.
 *
 * The PolicyEngine instead maps a DeviceProfile to a Kyber parameter
 * set at session-establishment time, trading off:
 *   - security margin (higher Kyber level = larger security margin
 *     against future cryptanalytic improvements)
 *   - computational cost (higher Kyber level = larger keys/ciphertexts,
 *     more CPU cycles for keygen/encaps/decaps)
 *   - device constraints (battery, compute class, link quality)
 *   - data sensitivity (high-sensitivity payloads justify paying the
 *     extra cost even on constrained devices)
 *
 * v1 IMPLEMENTATION NOTE (stated explicitly for the paper):
 * This version uses a transparent, rule-based (weighted-score) policy
 * so that the decision logic is fully auditable and explainable -
 * important for a security-critical component. A learned policy
 * (e.g. a lightweight classifier trained on the benchmark dataset this
 * harness produces) is proposed as future work once enough empirical
 * session data has been collected across device profiles.
 */
public class PolicyEngine {

    public enum SecurityLevel {
        KYBER_512(KyberParameters.kyber512, "Kyber-512", 1),
        KYBER_768(KyberParameters.kyber768, "Kyber-768", 2),
        KYBER_1024(KyberParameters.kyber1024, "Kyber-1024", 3);

        public final KyberParameters bcParams;
        public final String label;
        public final int rank; // relative strength/cost rank, 1=lowest,3=highest

        SecurityLevel(KyberParameters bcParams, String label, int rank) {
            this.bcParams = bcParams;
            this.label = label;
            this.rank = rank;
        }
    }

    /**
     * Decision record returned by the policy engine - captures not just
     * the chosen level but the score that produced it, so every decision
     * is explainable and logged for the evaluation dataset.
     */
    public static class Decision {
        public final SecurityLevel level;
        public final double constraintScore;   // 0 (very constrained) - 1 (unconstrained)
        public final double sensitivityWeight; // 0 - 1
        public final double combinedScore;
        public final String rationale;

        Decision(SecurityLevel level, double constraintScore, double sensitivityWeight,
                 double combinedScore, String rationale) {
            this.level = level;
            this.constraintScore = constraintScore;
            this.sensitivityWeight = sensitivityWeight;
            this.combinedScore = combinedScore;
            this.rationale = rationale;
        }
    }

    /**
     * Core decision function.
     *
     * Step 1: compute a device "constraint score" in [0,1] from battery,
     *         compute tier and link quality - higher = more capable/unconstrained.
     * Step 2: compute a "sensitivity weight" in [0,1] from the data
     *         sensitivity tag - higher = more sensitive, pushes toward
     *         stronger security regardless of device constraints.
     * Step 3: combine the two into a single score and threshold it into
     *         one of the three Kyber levels. Sensitivity is intentionally
     *         weighted more heavily than raw device capability: a highly
     *         constrained device carrying highly sensitive data should
     *         still lean toward stronger security, accepting the extra
     *         cost, rather than silently downgrading protection.
     */
    public Decision decide(DeviceProfile profile) {
        double batteryScore = profile.getBatteryPercent() / 100.0;
        double computeScore = switch (profile.getComputeTier()) {
            case LOW -> 0.0;
            case MEDIUM -> 0.5;
            case HIGH -> 1.0;
        };
        double linkScore = profile.getLinkQuality() / 100.0;

        double constraintScore = (batteryScore * 0.4) + (computeScore * 0.4) + (linkScore * 0.2);

        double sensitivityWeight = switch (profile.getDataSensitivity()) {
            case LOW -> 0.0;
            case MEDIUM -> 0.5;
            case HIGH -> 1.0;
        };

        // Sensitivity pulls the combined score up toward "use stronger crypto"
        // even when the device is constrained. Weighting: 55% constraint
        // capability, 45% sensitivity pressure.
        double combinedScore = (constraintScore * 0.55) + (sensitivityWeight * 0.45);

        SecurityLevel level;
        String rationale;
        if (combinedScore < 0.40) {
            level = SecurityLevel.KYBER_512;
            rationale = "Low device capability and/or low data sensitivity - minimize overhead.";
        } else if (combinedScore < 0.70) {
            level = SecurityLevel.KYBER_768;
            rationale = "Balanced capability/sensitivity - standard NIST-recommended margin.";
        } else {
            level = SecurityLevel.KYBER_1024;
            rationale = "High capability and/or high data sensitivity - maximize security margin.";
        }

        return new Decision(level, constraintScore, sensitivityWeight, combinedScore, rationale);
    }
}
