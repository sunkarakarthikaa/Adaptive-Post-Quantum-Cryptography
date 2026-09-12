import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Main
 * -----
 * End-to-end simulation of the AdaptivePQC architecture, now with the
 * comparison that makes the paper's central claim testable:
 *
 *   For every simulated device, we run FOUR conditions on the SAME
 *   fixed set of payloads:
 *     - STATIC_512  : force Kyber-512 regardless of device profile
 *     - STATIC_768  : force Kyber-768 regardless of device profile
 *     - STATIC_1024 : force Kyber-1024 regardless of device profile
 *     - ADAPTIVE    : use PolicyEngine's per-device decision
 *
 * This is the baseline comparison that was MISSING from the v1 build.
 * Without it there is no evidence for "adaptive selection is better
 * than static one-size-fits-all deployment" -- which is the paper's
 * core claim.
 *
 * METHODOLOGY FIXES vs the v1 build:
 *   1. JIT warm-up: a discarded warm-up phase runs the full pipeline
 *      repeatedly before any timed measurement.
 *   2. Fixed, shared payload sets per device across all four conditions.
 *   3. More trials per condition (30, up from 5) and mean/std-dev
 *      reporting instead of bare averages.
 *
 * SCOPE STILL UNCHANGED from the v1 build (see README "Honest Scope").
 */
public class Main {

    private static final int WARMUP_ITERATIONS = 60;
    private static final int TRIALS_PER_DEVICE_PER_CONDITION = 30;

    public static void main(String[] args) throws Exception {
        System.out.println("=== AdaptivePQC - Minimal Reference Implementation (v2: baseline comparison) ===");
        System.out.println("Hybrid AES-256-GCM + Kyber KEM with adaptive security-level policy engine\n");

        PolicyEngine policyEngine = new PolicyEngine();
        CryptoService cryptoService = new CryptoService();

        System.out.println("[Server] Generating Kyber identities for all supported levels...");
        Map<PolicyEngine.SecurityLevel, CryptoService.ServerIdentity> identities = new EnumMap<>(PolicyEngine.SecurityLevel.class);
        Map<PolicyEngine.SecurityLevel, Long> keyGenNanosByLevel = new EnumMap<>(PolicyEngine.SecurityLevel.class);
        for (PolicyEngine.SecurityLevel level : PolicyEngine.SecurityLevel.values()) {
            long t0 = System.nanoTime();
            CryptoService.ServerIdentity identity = cryptoService.generateServerIdentity(level);
            long t1 = System.nanoTime();
            identities.put(level, identity);
            keyGenNanosByLevel.put(level, t1 - t0);
            System.out.printf("  %-12s keypair generated in %.2f ms%n", level.label, (t1 - t0) / 1_000_000.0);
        }

        System.out.println("\n[Warm-up] Running " + WARMUP_ITERATIONS + " discarded iterations per Kyber level...");
        Random warmupRng = new Random(1);
        for (PolicyEngine.SecurityLevel level : PolicyEngine.SecurityLevel.values()) {
            CryptoService.ServerIdentity identity = identities.get(level);
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                byte[] payload = simulateSensorPayload(warmupRng);
                CryptoService.DeviceTiming dt = cryptoService.encryptForTransmission(payload, identity.publicKey);
                cryptoService.decryptTransmission(dt.transmission, identity.privateKey);
            }
        }
        System.out.println("[Warm-up] Complete.\n");

        List<DeviceProfile> fleet = buildSimulatedFleet();
        System.out.println("[Fleet] " + fleet.size() + " simulated devices across LOW/MEDIUM/HIGH compute tiers\n");

        List<SessionResult> results = new ArrayList<>();

        for (DeviceProfile profile : fleet) {
            PolicyEngine.Decision decision = policyEngine.decide(profile);

            Random deviceRng = new Random(profile.getDeviceId().hashCode());
            List<byte[]> payloads = new ArrayList<>(TRIALS_PER_DEVICE_PER_CONDITION);
            for (int i = 0; i < TRIALS_PER_DEVICE_PER_CONDITION; i++) {
                payloads.add(simulateSensorPayload(deviceRng));
            }

            System.out.println(profile);
            System.out.printf("  -> Adaptive policy decision: %s (score=%.3f) | %s%n",
                    decision.level.label, decision.combinedScore, decision.rationale);

            for (PolicyEngine.SecurityLevel staticLevel : PolicyEngine.SecurityLevel.values()) {
                String conditionName = "STATIC_" + staticLevel.name().substring("KYBER_".length());
                runCondition(conditionName, profile, staticLevel, payloads, identities,
                        keyGenNanosByLevel, cryptoService, decision.combinedScore, results);
            }
            runCondition("ADAPTIVE", profile, decision.level, payloads, identities,
                    keyGenNanosByLevel, cryptoService, decision.combinedScore, results);
        }

        String outPath = "logs/adaptivepqc_results.csv";
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath, StandardCharsets.UTF_8))) {
            pw.println(SessionResult.csvHeader());
            for (SessionResult r : results) pw.println(r.toCsvRow());
        }

        System.out.println("\n=== Summary (mean +/- std dev, " + TRIALS_PER_DEVICE_PER_CONDITION + " trials/device/condition) ===");
        long correctCount = results.stream().filter(r -> r.roundTripCorrect).count();
        System.out.println("Total sessions run: " + results.size());
        System.out.println("Correct round-trips: " + correctCount + " / " + results.size());
        System.out.println();

        // NOTE ON STATISTICS: the per-session total-latency distribution on a
        // JVM is heavily right-skewed in practice (GC pauses, safepoints, OS
        // scheduling jitter produce a long tail of slow outliers) -- this is
        // a well-known property of JVM microbenchmarking, not a bug in this
        // harness. Mean +/- std dev is reported for completeness, but the
        // median and p95/p99 are the numbers that should actually be cited
        // in the paper's evaluation section, since the mean is pulled upward
        // by a small number of tail-latency sessions that are not
        // representative of typical performance.
        for (String condition : List.of("STATIC_512", "STATIC_768", "STATIC_1024", "ADAPTIVE")) {
            List<SessionResult> subset = results.stream().filter(r -> r.condition.equals(condition)).toList();
            if (subset.isEmpty()) continue;

            double[] totalMicros = subset.stream()
                    .mapToDouble(r -> (r.encapsulateNanos + r.aesEncryptNanos + r.decapsulateNanos + r.aesDecryptNanos) / 1000.0)
                    .toArray();
            double meanTotal = mean(totalMicros);
            double sdTotal = stdDev(totalMicros, meanTotal);
            double[] sorted = totalMicros.clone();
            Arrays.sort(sorted);
            double median = percentile(sorted, 0.50);
            double p95 = percentile(sorted, 0.95);
            double p99 = percentile(sorted, 0.99);

            double avgSecurityRank = subset.stream().mapToInt(r -> r.securityRank).average().orElse(0);
            int avgCipherBytes = subset.stream().mapToInt(r -> r.kyberCiphertextBytes).sum() / subset.size();

            System.out.printf("%-12s n=%-4d mean=%.1f sd=%.1f median=%.1f p95=%.1f p99=%.1f avgSecurityRank=%.2f avgCipherBytes=%d%n",
                    condition, subset.size(), meanTotal, sdTotal, median, p95, p99, avgSecurityRank, avgCipherBytes);
        }

        System.out.println("\n=== Adaptive vs. Static comparison (the paper's core claim) ===");
        System.out.println("(using MEDIAN latency -- the statistically appropriate summary for this");
        System.out.println(" right-skewed JVM timing distribution; see note above)");
        double adaptiveMedian = medianTotalMicros(results, "ADAPTIVE");
        double static512Median = medianTotalMicros(results, "STATIC_512");
        double static1024Median = medianTotalMicros(results, "STATIC_1024");
        double adaptiveAvgRank = avgSecurityRank(results, "ADAPTIVE");

        System.out.printf("ADAPTIVE vs STATIC_512  (cheapest, weakest):  %+.1f%% latency, rank %.2f vs 1.00%n",
                percentDiff(adaptiveMedian, static512Median), adaptiveAvgRank);
        System.out.printf("ADAPTIVE vs STATIC_1024 (strongest, priciest): %+.1f%% latency, rank %.2f vs 3.00%n",
                percentDiff(adaptiveMedian, static1024Median), adaptiveAvgRank);
        System.out.println("(negative %% = ADAPTIVE is faster/cheaper than that static baseline)");

        System.out.println("\nFull results written to: " + outPath);
        System.out.println("This CSV is the real evaluation dataset -- use it for the paper's evaluation section.");
    }

    private static void runCondition(String conditionName, DeviceProfile profile,
                                      PolicyEngine.SecurityLevel level, List<byte[]> payloads,
                                      Map<PolicyEngine.SecurityLevel, CryptoService.ServerIdentity> identities,
                                      Map<PolicyEngine.SecurityLevel, Long> keyGenNanosByLevel,
                                      CryptoService cryptoService, double combinedScore,
                                      List<SessionResult> results) throws Exception {
        CryptoService.ServerIdentity identity = identities.get(level);
        for (byte[] payload : payloads) {
            CryptoService.DeviceTiming deviceTiming = cryptoService.encryptForTransmission(payload, identity.publicKey);
            CryptoService.ServerTiming serverTiming = cryptoService.decryptTransmission(deviceTiming.transmission, identity.privateKey);
            boolean correct = Arrays.equals(payload, serverTiming.payload);

            results.add(new SessionResult(
                    conditionName, profile.getDeviceId(), profile.getComputeTier().name(),
                    profile.getBatteryPercent(), profile.getLinkQuality(),
                    profile.getDataSensitivity().name(), level.label, level.rank, combinedScore,
                    keyGenNanosByLevel.get(level),
                    deviceTiming.kyberEncapsulateNanos, deviceTiming.aesEncryptNanos,
                    serverTiming.kyberDecapsulateNanos, serverTiming.aesDecryptNanos,
                    payload.length, deviceTiming.transmission.kyberEncapsulation.length, correct));

            if (!correct) {
                System.err.println("  !! ROUND-TRIP MISMATCH: " + conditionName + " / " + profile.getDeviceId());
            }
        }
    }

    private static double mean(double[] values) {
        return Arrays.stream(values).average().orElse(0);
    }

    private static double stdDev(double[] values, double mean) {
        if (values.length < 2) return 0;
        double sumSq = 0;
        for (double v : values) sumSq += (v - mean) * (v - mean);
        return Math.sqrt(sumSq / (values.length - 1));
    }

    /** sortedValues must already be sorted ascending. */
    private static double percentile(double[] sortedValues, double p) {
        int idx = (int) Math.ceil(p * sortedValues.length) - 1;
        idx = Math.max(0, Math.min(sortedValues.length - 1, idx));
        return sortedValues[idx];
    }



    private static double medianTotalMicros(List<SessionResult> results, String condition) {
        double[] vals = results.stream().filter(r -> r.condition.equals(condition))
                .mapToDouble(r -> (r.encapsulateNanos + r.aesEncryptNanos + r.decapsulateNanos + r.aesDecryptNanos) / 1000.0)
                .toArray();
        Arrays.sort(vals);
        return percentile(vals, 0.50);
    }

    private static double avgSecurityRank(List<SessionResult> results, String condition) {
        return results.stream().filter(r -> r.condition.equals(condition))
                .mapToInt(r -> r.securityRank).average().orElse(0);
    }

    private static double percentDiff(double value, double baseline) {
        return ((value - baseline) / baseline) * 100.0;
    }

    private static List<DeviceProfile> buildSimulatedFleet() {
        List<DeviceProfile> fleet = new ArrayList<>();
        int id = 1;
        for (DeviceProfile.ComputeTier tier : DeviceProfile.ComputeTier.values()) {
            for (DeviceProfile.Sensitivity sens : DeviceProfile.Sensitivity.values()) {
                fleet.add(new DeviceProfile("dev-" + (id++), 15, tier, 30, sens));
                fleet.add(new DeviceProfile("dev-" + (id++), 55, tier, 60, sens));
                fleet.add(new DeviceProfile("dev-" + (id++), 90, tier, 95, sens));
            }
        }
        return fleet;
    }

    private static byte[] simulateSensorPayload(Random rng) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ts\":").append(System.currentTimeMillis());
        sb.append(",\"temp\":").append(15 + rng.nextDouble() * 20);
        sb.append(",\"humidity\":").append(30 + rng.nextDouble() * 50);
        sb.append(",\"battery\":").append(rng.nextInt(100));
        int extraReadings = 5 + rng.nextInt(50);
        sb.append(",\"readings\":[");
        for (int i = 0; i < extraReadings; i++) {
            if (i > 0) sb.append(",");
            sb.append(String.format("%.2f", rng.nextDouble() * 100));
        }
        sb.append("]}");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
}
